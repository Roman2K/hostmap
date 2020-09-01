require 'net_x/http_unix'
require 'pp'
require 'utils'
require 'base64'
require 'bcrypt'

class Cmds
  ALIASES_CONF_PATH = "config.dev_aliases.yml"
  DEFAULT_DOCKER_URI = URI "unix:///var/run/docker.sock"

  def initialize(config)
    @config = config
    @log = Utils::Log.new
  end

  def cmd_gen
    conf = @config["caddy"]
    caddy = CaddyClient.new conf["admin_url"], log: @log
    docker = DockerClient.new \
      URI(conf.lookup("docker_uri") || DEFAULT_DOCKER_URI)

    user_defs = conf["users"].to_hash.transform_keys &:to_s
    services = conf["services.static"].to_hash

    docker.get_json("/containers/json").each do |props|
      ctn = Container.new props
      next unless ctn.hostmap_enable && !ctn.oneoff
      port = ctn.private_port or next
      svc = ctn.service_name or next
      clog = @log[svc: svc]
      svc.length >= 1 or raise "invalid service name: %p" % [svc]
      raise "duplicate service: %p" % [svc] if services.key? svc
      clog.warn "not in caddy network" unless ctn.networks.include? "caddy"
      services[svc] = {
        uri: "#{svc}:#{port}",
        users: ctn.users,
      }
    end

    routes = services.flat_map do |name, info|
      info = {uri: info} unless Hash === info
      users = info.fetch(:users, []).map do |u|
        passwd = user_defs.fetch(u) { raise "undefined user: #{u}" }
        [u, passwd]
      end

      domains = if users.empty?
        {false => conf["domains"]}
      else
        conf["domains"].group_by { _1[:internal] }
      end

      domains.flat_map do |int, doms|
        { match: [
            {host: doms.map { |d| "#{name}.#{d[:domain]}" }},
          ],
          handle: [
            (auth_handler(users) if !int && !users.empty?),
            reverse_proxy_handler(info.fetch :uri),
          ].compact }
      end
    end

    if conf["ro"]
      pp routes: routes
      return
    end
    caddy.set_config "/apps/http/servers/main/routes", routes
  end

  private def auth_handler(users)
    { handler: "authentication",
      providers: {
        http_basic: {
          hash: {algorithm: "bcrypt"},
          accounts: users.map { |username, passwd|
            passwd = Base64.strict_encode64 BCrypt::Password.create(passwd)
            { username: username,
              password: passwd }
          }
        }
      } }
  end

  private def reverse_proxy_handler(uri)
    explicit = true
    unless uri.include? "://"
      uri = URI "http://#{uri}" 
      explicit = false
    end
    case uri = URI(uri)
    when URI::HTTPS then https = true
    when URI::HTTP
    else raise "unhandled scheme: #{uri}"
    end
    { handler: "reverse_proxy",
      upstreams: [
        {dial: "#{uri.host}:#{uri.port}"},
      ],
      transport: {protocol: "http"}.tap { |h|
        h[:tls] = {
          root_ca_pem_files: ["/etc/ssl/certs/ca-certificates.crt"],
          server_name: uri.host,
          insecure_skip_verify: true,
        } if https
      },
      headers: {
        request: {
          set: {}.tap do |h|
            h["Host"] = ["#{uri.host}:#{uri.port}"] if explicit
            h["Authorization"] = [
              "Basic #{Base64.strict_encode64 "#{uri.user}:#{uri.password}"}",
            ] if uri.user
          end
        }
      } }
  end
end

class DockerClient
  API_VER = "1.40"

  def initialize(uri)
    uri = NetX::HTTPUnix.new 'unix://' + uri.path if uri.scheme == 'unix'
    @client = Utils::SimpleHTTP.new uri, json: true
  end

  def get_json(path)
    @client.get path
  end
end

class Container
  LABEL_PREFIX = "hostmap"

  def initialize(props)
    labels = props.fetch "Labels"
    project = labels["com.docker.compose.project"]

    @oneoff = labels["com.docker.compose.oneoff"] == "True"
    @hostmap_enable = labels["#{LABEL_PREFIX}.enable"] == "True"
    @service_name = labels["com.docker.compose.service"]
    @private_port = determine_port(props.fetch("Ports"), labels)
    @networks =
      props.fetch("NetworkSettings").fetch("Networks").keys.tap { |arr|
        arr.map! { _1.sub /^#{Regexp.escape project}_/, "" } if project
      }
    @users = labels["#{LABEL_PREFIX}.users"].to_s.split(",").map &:strip
  end

  attr_reader \
    :oneoff,
    :hostmap_enable,
    :service_name,
    :private_port,
    :networks,
    :users

  private def determine_port(ports, labels)
    labels["#{LABEL_PREFIX}.port"]&.to_i \
      || ports.find { |p| p.fetch("Type") == "tcp" }&.fetch("PrivatePort")
  end
end

class CaddyClient
  def initialize(url, log:)
    @client = Utils::SimpleHTTP.new url, json: true
    @log = log["caddy"]
  end

  def config
    @client.get "/config/"
  end

  def set_config(path, config)
    @log.info "updating config:\n%s" % [PP.pp(config, "")]
    @client.patch "/config#{path}", config, expect: [Net::HTTPOK],
      json_out: false
  end
end

if $0 == __FILE__
  Cmds.new(Utils::Conf.new "config.yml").cmd_gen
end

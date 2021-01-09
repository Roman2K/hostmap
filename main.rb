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
    docker = Utils::DockerClient.new \
      URI(conf.lookup("docker_uri") || DEFAULT_DOCKER_URI),
      log: @log["docker"]

    user_defs = conf["users"].to_hash.transform_keys &:to_s
    services = conf["services.static"].to_hash

    docker.get_json("/containers/json").
      flat_map { |props| Container.new(props, log: @log).hostmaps }.
      each { |hm|
        services[hm.domain] = {
          uri: "#{hm.service}:#{hm.port}",
          users: hm.users,
          force_auth: hm.force_auth,
        }
      }

    routes = services.flat_map do |name, info|
      info = {uri: info, force_auth: false} unless Hash === info

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
        want_auth = info.fetch(:force_auth) || !int
        { match: [
            {host: doms.map { |d| "#{name}.#{d[:domain]}" }},
          ],
          handle: [
            (auth_handler(users) if !users.empty? && want_auth),
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

class Container
  HOSTMAP_PREFIX = "hostmap"
  DOCKER_TRUE = "True"

  def initialize(props, log:)
    labels = props.fetch "Labels"
    ports = props.fetch "Ports"
    oneoff = labels["com.docker.compose.oneoff"] == DOCKER_TRUE
    project = labels["com.docker.compose.project"]

    @service_name = labels["com.docker.compose.service"]
    @log = log[service: @service_name]

    @networks =
      props.fetch("NetworkSettings").fetch("Networks").keys.tap do |arr|
        arr.map! { _1.sub /^#{Regexp.escape project}_/, "" } if project
      end
    @hostmaps = [].tap do
      _1.concat build_hostmaps(labels, ports) unless oneoff
    end
  end

  attr_reader :hostmaps

  private def build_hostmaps(labels, ports)
    labels = self.class.nested_labels(labels).fetch(HOSTMAP_PREFIX, {})
    defs = labels.delete("as") || {}
    defs[@service_name] ||= labels if !labels.empty?

    defs.filter_map do |domain, props|
      if val = props.delete("enable") and val != DOCKER_TRUE
        next
      end
      port = props.delete("port")&.to_i \
        || ports.find { |p| p.fetch("Type") == "tcp" }&.fetch("PrivatePort") \
        or next
      users = props.delete("users").to_s.split(",").map &:strip
      force_auth = props.delete("force_auth") == DOCKER_TRUE
      dlog = @log[domain: domain]
      dlog.warn "not in caddy network" unless @networks.include? "caddy"
      props.empty? or raise "extra hostmap properties: #{props.keys.join ", "}"

      Hostmap.new \
        service: @service_name,
        domain: domain,
        port: port,
        users: users,
        force_auth: force_auth
    end
  end

  Hostmap = Struct.new :service, :domain, :port, :users, :force_auth,
    keyword_init: true

  def self.nested_labels(labels)
    hash = {}
    labels.each do |key, val|
      *hier, last_k = key.split "."
      dest = hier.inject(hash) do |h,k|
        h.delete(k) unless Hash === h[k]; h[k] ||= {}
      end
      dest[last_k] = val
    end
    hash
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

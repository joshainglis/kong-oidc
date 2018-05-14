local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")

local cjson = require("cjson")

OidcHandler.PRIORITY = 1000


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  if oidcConfig.introspection_endpoint then
    response = introspect(oidcConfig)
    if response then
      utils.injectUser(response)
    end
  end

  if response == nil then
    response = make_oidc(oidcConfig)
    if response and response.user then
      utils.injectUser(response.user)
      ngx.log(ngx.INFO, "Got userinfo: " .. cjson.encode(response.user))
      ngx.req.set_header("X-Userinfo", cjson.encode(response.user))
    end
    ngx.log(ngx.INFO, "Failed to get userinfo: " .. response)
  end
end

function make_oidc(oidcConfig)
  ngx.log(ngx.INFO, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = require("resty.openidc").authenticate(oidcConfig)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.INFO, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function introspect(oidcConfig)
  if utils.has_bearer_access_token() then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      ngx.log(ngx.INFO, "OidcHandler introspect failed: " ..  " requested path: " .. ngx.var.request_uri)
      return nil
    end
    ngx.log(ngx.INFO, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  ngx.log(ngx.INFO, "OidcHandler introspect failed, No bearer token found: " .. ngx.var.request_uri)
  return nil
end


return OidcHandler

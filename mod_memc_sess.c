#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apreq2/apreq_cookie.h"
#include "libmemcached/memcached.h"

#define ERR_MSG_HEAD "MemcSess: "
#define ERR_MSG_NO_MEMCACHED_SERVER (ERR_MSG_HEAD "Memcached host is empty ")
#define ERR_MSG_NO_SESSION_KEY_NAME (ERR_MSG_HEAD "Session key name is empty ")
#define ERR_MSG_NO_MEMCACHE_KEY_PREFIX (ERR_MSG_HEAD "Memcache key prefix is empty ")

#define ERRLOG(...) ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, __VA_ARGS__)
#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, __VA_ARGS__)

typedef struct {
  const char *memcached_server;
  const char *session_key_name;
  const char *memcache_key_prefix;
} memc_sess_conf;

extern module AP_MODULE_DECLARE_DATA memc_sess_module;

/*
 * configuration
 */
static void *create_memc_sess_conf(apr_pool_t *p, server_rec *s)
{
  return apr_pcalloc(p, sizeof(memc_sess_conf));
}

static memc_sess_conf *conf_from_req(request_rec *r)
{
  return ap_get_module_config(r->server->module_config, &memc_sess_module);
}

static const char *get_memcached_server(request_rec *r)
{
  return conf_from_req(r)->memcached_server;
}

static const char *get_session_key_name(request_rec *r)
{
  return conf_from_req(r)->session_key_name;
}

static const char *get_memcache_key_prefix(request_rec *r)
{
  return conf_from_req(r)->memcache_key_prefix;
}

/*
 * cookie
 */
static const char *get_session_key_from_cookie(request_rec *r, 
                                               const char *key_name)
{
  apr_status_t st;
  apr_table_t *cookie_jar;
  const char *cookie_string;
  const char *cookie_value;

  cookie_string = apr_table_get(r->headers_in, "Cookie");
  if (!cookie_string)
    return NULL;

  cookie_jar = apr_table_make(r->pool, 1);
  st = apreq_parse_cookie_header(r->pool, cookie_jar, cookie_string);
  if (st != APR_SUCCESS) {
    char buf[512];
    apreq_strerror(st, buf, sizeof(buf));
    ERRLOG((ERR_MSG_HEAD "apreq_parse_cookie_header error. %s "), buf);
    return NULL;
  }

  cookie_value = apr_table_get(cookie_jar, key_name);
  if (!cookie_value)
    return NULL;

  return cookie_value;
}

/*
 * memcached-client
 */
static int memc_get_session(request_rec *r, const char *memcached_server,
                            const char *key, const int vlen, char *val)
{
  int flags;
  char *res;
  size_t reslen; 
  size_t klen = strlen(key);
  struct memcached_st *memc = NULL;
  struct memcached_server_st *memc_srv = NULL;
  memcached_return rc;
  int ret = 1;

#define RETURN(r) { ret = r; goto clean; }
  
  memc = memcached_create(NULL);
  memc_srv = memcached_servers_parse((char *)memcached_server);
  rc = memcached_server_push(memc, memc_srv);

  if(rc != MEMCACHED_SUCCESS) {
    ERRLOG((ERR_MSG_HEAD "memcached_server_push error. %s "),
           memcached_strerror(memc, rc));
    RETURN(-1);
  }

  res = memcached_get(memc, key, klen, &reslen, &flags, &rc);
  if (rc != MEMCACHED_SUCCESS) {
    if (rc != MEMCACHED_NOTFOUND) {
      RETURN(0);
    }
    else {
      ERRLOG((ERR_MSG_HEAD "memcached_get error. %s "),
             memcached_strerror(memc, rc));
      RETURN(-1);
    }
  }
  strncpy(val, res, reslen > vlen ? vlen : reslen);

clean:
  if (memc_srv)
    memcached_server_list_free(memc_srv);

  if (memc)
    memcached_free(memc);

  return ret;
}

/*
 * hooks
 */
static int memc_sess_handler(request_rec *r)
{
  int rc;
  const char *memcached_server = get_memcached_server(r);
  const char *session_key_name = get_session_key_name(r);
  const char *memcache_key_prefix = get_memcache_key_prefix(r);
  const char *session_key;
  char session_key_buf[256];
  char buf[1024];

  if (!memcached_server) {
    DEBUGLOG(ERR_MSG_NO_MEMCACHED_SERVER);
    return DECLINED;
  }

  if (!session_key_name) {
    DEBUGLOG(ERR_MSG_NO_SESSION_KEY_NAME);
    return DECLINED;
  }

  if ((session_key = get_session_key_from_cookie(r, session_key_name)) &&
      memcache_key_prefix) {
    snprintf(session_key_buf, sizeof(session_key_buf),
             "%s%s", memcache_key_prefix, session_key);
    session_key = session_key_buf;
  }

  if (session_key) {
    switch (
      memc_get_session(r, memcached_server, session_key, sizeof(buf), buf)
    ) {
      case 0:
        return HTTP_UNAUTHORIZED;
      case 1:
        break;
      default:
        return HTTP_INTERNAL_SERVER_ERROR;
    }
  }
  else {
    return HTTP_UNAUTHORIZED;
  }

  return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_access_checker(memc_sess_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 * commands
 */
static memc_sess_conf *conf_from_cmd(cmd_parms *cmd)
{
  return ap_get_module_config(cmd->server->module_config, &memc_sess_module);
}

static const char *cmd_memcached_server(cmd_parms *cmd, void *config,
                                      const char *arg1)
{
  memc_sess_conf *conf = conf_from_cmd(cmd);
  if (!(conf->memcached_server = arg1)) {
    return (const char*)apr_pstrcat(
        cmd->pool, ERR_MSG_NO_MEMCACHED_SERVER, arg1, NULL);
  }
  return NULL;
}

static const char *cmd_session_key_name(cmd_parms *cmd, void *config,
                                   const char *arg1)
{
  memc_sess_conf *conf = conf_from_cmd(cmd);
  if (!(conf->session_key_name = arg1)) {
    return (const char*)apr_pstrcat(
        cmd->pool, ERR_MSG_NO_SESSION_KEY_NAME, arg1, NULL);
  }
  return NULL;
}

static const char *cmd_memcache_key_prefix(cmd_parms *cmd, void *config,
                                   const char *arg1)
{
  memc_sess_conf *conf = conf_from_cmd(cmd);
  if (!(conf->memcache_key_prefix = arg1)) {
    return (const char*)apr_pstrcat(
        cmd->pool, ERR_MSG_NO_MEMCACHE_KEY_PREFIX, arg1, NULL);
  }
  return NULL;
}

static const command_rec memc_sess_cmds[] =
{
  AP_INIT_TAKE1("MemcachedServer", cmd_memcached_server, NULL, ACCESS_CONF,
                "specify host and port of a memcached"),
  AP_INIT_TAKE1("SessionKeyName", cmd_session_key_name, NULL, ACCESS_CONF,
                "specify a session key name"),
  AP_INIT_TAKE1("MemcacheKeyPrefix", cmd_memcache_key_prefix, NULL, ACCESS_CONF,
                "specify a memcache key prefix"),
  { NULL }
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA memc_sess_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    create_memc_sess_conf, /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    memc_sess_cmds,        /* table of config file commands       */
    register_hooks         /* register hooks                      */
};


#!/usr/bin/env python
import kopf
import kubernetes
import jinja2
import base64
import random
import string
import passlib.hash
from prometheus_client import start_http_server

def generate_name(name, namespace):
    return "password-{name}-from-{namespace}".format(name=name, namespace=namespace)

def generate_password(length):
    symbols = string.digits + string.ascii_letters + "%+-,.;:<=>@^_"
    password = "".join(random.SystemRandom().choice(symbols) for i in range(length))
    return password

def read_types(secret):
    types = list(secret.data)
    types.remove('password')
    return sorted(types)

def read_types_from_password(password):
    return sorted(password.get('types',[]))


def base(data):
   return base64.b64encode(data.encode()).decode() 

def generate_crypt(password, method, logger):
    crypt_name = method + "_crypt" 
    try:
        logger.debug("looking for passlib.hash.{crypt_name}".format(crypt_name=crypt_name))
        crypt_fn = getattr(passlib.hash, crypt_name).hash
        logger.debug("generating {method} password".format(method=method))
        return base(crypt_fn(password))
    except AttributeError as e:
        #logger.warning("crypt method {method} not found".format(method=method))
        logger.warning(e)
        raise
        
def generate_body(spec, name, namespace, logger):
    password = generate_password(32)
    data={
        'password': base(password)
    }
    #logger.info("AAA")
    #logger.info(spec)
    #logger.info("BBB0")
    for method in spec.get('types', []):
        try:
            data[method] = generate_crypt(password, method, logger)
        except AttributeError:
            pass
    #logger.info("CCC")
    body=kubernetes.client.V1Secret(
        metadata=kubernetes.client.V1ObjectMeta(
            name=generate_name(name, namespace),
            labels={
                'password': name,
                'source_namespace': namespace,
                'creator': 'password-generator',
                'role': 'source',
            }
        ),
        data=data
    )
    #logger.info("DDD")
    # passlib.hash.ldap_sha512_crypt.hash("asd123")
    return body

def find_cloned_namespaces(secrets):
    namespaces = []
    for secret in secrets:
        namespaces.append(secret.metadata.namespace)
    return namespaces

def read_namespaces_from_password(password):
    return sorted(password.get('copy_namespaces',[]))

def strip_extra_fields(secret):
    #del(secret.metadata['creation_timestamp'])
    #del(secret.metadata['managed_fields'])
    #del(secret.metadata['resource_version'])
    #del(secret.metadata['self_link'])
    #del(secret.metadata['uid'])

    secret.metadata.creation_timestamp = None
    secret.metadata.managed_fields = None
    secret.metadata.resource_version = None
    secret.metadata.self_link = None
    secret.metadata.uid = None
    return secret


@kopf.on.resume('exphost.pl','v1','passwords')
@kopf.on.create('exphost.pl','v1','passwords')
@kopf.on.update('exphost.pl','v1','passwords')
@kopf.timer('exphost.pl','v1','passwords', interval=30.0)
def create_fn(spec, name, namespace ,logger, **kwargs):
    logger.info(f"passwords creates: {spec}, {name}, {namespace}")
    api = kubernetes.client.CoreV1Api()
    sec_name = generate_name(name, namespace)
    body=generate_body(spec, name, namespace, logger)
    # read existing secret. if not exists, create and read
    try:
        secret = api.read_namespaced_secret(sec_name, namespace)
        #logger.info(secret)
    except kubernetes.client.exceptions.ApiException as e:
        if e.status != 404:
            raise
        #logger.info("Body: {body}".format(body=body))
        api.create_namespaced_secret(namespace, body)
        secret = api.read_namespaced_secret(sec_name, namespace)

    secret = strip_extra_fields(secret)
    existing_types = read_types(secret)
    desired_types = read_types_from_password(spec)
    if existing_types != desired_types:
        missing, extra = set(desired_types)-set(existing_types), set(existing_types)-set(desired_types)
        logger.info("types: missing={missing}, extra={extra}".format(missing=missing, extra=extra))
        for crypt in extra:
            del(secret.data[crypt])
        for crypt in missing:
            try:
                password = base64.b64decode(secret.data['password'].encode()).decode()
                secret.data[crypt] = generate_crypt(password, crypt, logger)
            except AttributeError:
                pass
        patch = api.replace_namespaced_secret(sec_name, namespace, secret)
    
    # change role to replica for easier comparastins
    secret.metadata.labels['role'] = 'clone'
    secret.metadata.namespace = None
    cloned_secrets = api.list_secret_for_all_namespaces(label_selector="creator=password-generator,role=clone,password={pass_name}".format(pass_name=name)).items
    #logger.info("label_selector={selector}".format(selector="creator=password-generator,role=clone,password={pass_name}".format(pass_name=name)))
    #logger.info('cloned_secrets: {cloned}'.format(cloned=cloned_secrets))
    existing_namespaces = set(find_cloned_namespaces(cloned_secrets))
    desired_namespaces = set(read_namespaces_from_password(spec))
    if existing_namespaces != desired_namespaces:
        missing, extra = set(desired_namespaces)-set(existing_namespaces), set(existing_namespaces)-set(desired_namespaces)
        logger.info("namespaces: missing={missing}, extra={extra}".format(missing=missing, extra=extra))
        for ns in missing:
            try:
                logger.info("creating secret {name} in {namespace}".format(name=secret.metadata.name, namespace=ns))
                api.create_namespaced_secret(ns, secret)
            except kubernetes.client.exceptions.ApiException as e:
                if e.status != 404:
                    raise
                logger.warning("Namespace {ns} does not exists".format(ns=ns))
        for ns in extra:
            logger.info("deleting secret {name} in {namespace}".format(name=secret.metadata.name, namespace=ns))
            api.delete_namespaced_secret(secret.metadata.name, ns)
    for cloned_secret in cloned_secrets:
        if cloned_secret.data != secret.data:
            logger.info("secret {name} different from source. replacing...".format(name=cloned_secret.metadata.name))
            api.replace_namespaced_secret(cloned_secret.metadata.name, cloned_secret.metadata.namespace, secret)

start_http_server(8000)

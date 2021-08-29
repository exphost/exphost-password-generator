#!/usr/bin/env python
import kopf
import kubernetes
import jinja2
import base64

@kopf.on.resume('exphost.pl','v1','passwords')
@kopf.on.create('exphost.pl','v1','passwords')
@kopf.on.update('exphost.pl','v1','passwords')
@kopf.timer('exphost.pl','v1','templates', interval=60.0)
def create_fn(spec, name, namespace ,logger, **kwargs):
    logger.info(f"passwords creates: {spec}, {name}, {namespace}")
#    api = kubernetes.client.CoreV1Api()
#    values = {}
#    try:
#        for val in spec['values']:
#            logger.info(f"looking for: {val}")
#            if val['source_type'] == "ConfigMap":
#                source = api.read_namespaced_config_map(val['source_name'], namespace)
#                values[val['name']] = source.data[val['source_key']]
#            elif val['source_type'] == "Secret":
#                source = api.read_namespaced_secret(val['source_name'], namespace)
#                values[val['name']] = base64.b64decode(source.data[val['source_key']]).decode()
#        logger.info(f"got values: {values}")
#        if spec['destination_type'] == "ConfigMap":
#            dest_obj = kubernetes.client.V1ConfigMap
#            list_func = api.list_namespaced_config_map
#            read_func = api.read_namespaced_config_map
#            patch_func = api.patch_namespaced_config_map
#            create_func = api.create_namespaced_config_map
#            def hash(data):
#                return data
#        elif spec['destination_type'] == "Secret":
#            dest_obj = kubernetes.client.V1Secret
#            list_func = api.list_namespaced_secret
#            read_func = api.read_namespaced_secret
#            patch_func = api.patch_namespaced_secret
#            create_func = api.create_namespaced_secret
#            def hash(data):
#                return base64.b64encode(data.encode()).decode()
#        manifest= {
#            'namespace': namespace,
#            'body': dest_obj(
#                metadata=kubernetes.client.V1ObjectMeta(
#                    name=spec['destination_name'],
#                ),
#                data={ spec['destination_key']: hash(jinja2.Template(spec['template']).render(values)) }
#            )
#        }
#        logger.info("rendered content: {manifest}".format(manifest=manifest['body'].data))
#        if len(list(filter(lambda x: x.metadata.name == spec['destination_name'], list_func(namespace).items))):
#            logger.info("{type} {name} exists".format(type=spec['destination_type'], name=spec['destination_name']))
#            bo = read_func(spec['destination_name'], namespace)
#            different = (bo.data != manifest['body'].data)
#            logger.info("Diff? {diff}".format(diff=different))
#            if different:
#                patch = patch_func(spec['destination_name'], namespace, manifest['body'])
#                logger.info("Patch: {patch}".format(patch=patch))
#        else:
#            logger.info("creating {type} {name}".format(type=spec['destination_type'], name=spec['destination_name']))
#            create_func(**manifest)
#            
#    except kubernetes.client.exceptions.ApiException as e:
#        logger.error(f"Error while reading {val}: {e}")
#

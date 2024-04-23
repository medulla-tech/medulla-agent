INSERT INTO mon_device_service (device_type, structure_json_controle) VALUES ('system', '
"general_status": "info",
"services": {
    "ejabberd": { "status": bool, "cpu": percentage, "memory": bytes, "nbopenfiles": number },
    "syncthing": { "status": bool, "cpu": percentage, "memory": bytes },
    "apache": { "status": bool, "cpu": percentage, "memory": bytes },
    "tomcat": { "status": bool, "cpu": percentage, "memory": bytes },
    "ssh": { "status": bool, "cpu": percentage, "memory": bytes },
    "openldap": { "status": bool, "cpu": percentage, "memory": bytes },
    "mysql": { "status": bool, "cpu": percentage, "memory": bytes, "nbopenfiles": number },
    "mmc-agent": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-agent-relay": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-package-watching": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-inventory-server": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-package-server": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-inventory": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration2": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration3": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration4": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration5": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration6": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration7": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration8": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration9": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-registration10": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger2": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger3": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger4": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger5": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger6": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger7": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger8": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger9": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-logger10": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-monitoring": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor2": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor3": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor4": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor5": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor6": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor7": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor8": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor9": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-assessor10": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-reconfigurator": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment2": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment3": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment4": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment5": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment6": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment7": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment8": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment9": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-deployment10": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription2": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription3": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription4": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription5": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription6": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription7": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription8": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription9": { "status": bool, "cpu": percentage, "memory": bytes },
    "medulla-master-substitute-subscription10": { "status": bool, "cpu": percentage, "memory": bytes }
},
"ports": {
    "ejabberd-c2s": bool,
    "ejabberd-s2s": bool,
    "syncthing": bool,
    "syncthing-web": bool,
    "syncthing-discosrv": bool,
    "apache": bool,
    "apache-ssl": bool,
    "tomcat": bool,
    "ssh": bool,
    "mysql": bool,
    "mmc-agent": bool,
    "medulla-inventory-server": bool,
    "medulla-package-server": bool
},
"resources": {
    "cpu" : percentage,
    "memory": { "total": bytes, "available": bytes, "used": bytes, "free": bytes, "percent": percentage },
    "swap": {"total": bytes, "used": bytes, "free": bytes, "percent": percentage },
    "df_": { "total": kilobytes, "used": kilobytes, "free": kilobytes, "percent": percentage },
    "df_var": { "total": kilobytes, "used": kilobytes, "free": kilobytes, "percent": percentage },
    "df_tmp": { "total": kilobytes, "used": kilobytes, "free": kilobytes, "percent": percentage }
},
"ejabberd": {
    "connected_users": number,
    "registered_users": number,
    "offline_count_rs": number,
    "offline_count_master": number,
    "offline_count_master_inv": number,
    "offline_count_master_mon": number,
    "offline_count_master_reconf": number,
    "offline_count_master_reg": number,
    "offline_count_master_reg2": number,
    "offline_count_master_reg3": number,
    "offline_count_master_reg4": number,
    "offline_count_master_reg5": number,
    "offline_count_master_reg6": number,
    "offline_count_master_reg7": number,
    "offline_count_master_reg8": number,
    "offline_count_master_reg9": number,
    "offline_count_master_reg10": number,
    "offline_count_master_subs": number,
    "offline_count_master_subs2": number,
    "offline_count_master_subs3": number,
    "offline_count_master_subs4": number,
    "offline_count_master_subs5": number,
    "offline_count_master_subs6": number,
    "offline_count_master_subs7": number,
    "offline_count_master_subs8": number,
    "offline_count_master_subs9": number,
    "offline_count_master_subs10": number,
    "offline_count_master_asse": number,
    "offline_count_master_asse2": number,
    "offline_count_master_asse3": number,
    "offline_count_master_asse4": number,
    "offline_count_master_asse5": number,
    "offline_count_master_asse6": number,
    "offline_count_master_asse7": number,
    "offline_count_master_asse8": number,
    "offline_count_master_asse9": number,
    "offline_count_master_asse10": number,
    "offline_count_master_depl": number,
    "offline_count_master_depl2": number,
    "offline_count_master_depl3": number,
    "offline_count_master_depl4": number,
    "offline_count_master_depl5": number,
    "offline_count_master_depl6": number,
    "offline_count_master_depl7": number,
    "offline_count_master_depl8": number,
    "offline_count_master_depl9": number,
    "offline_count_master_depl10": number,
    "offline_count_master_log": number,
    "offline_count_master_log2": number,
    "offline_count_master_log3": number,
    "offline_count_master_log4": number,
    "offline_count_master_log5": number,
    "offline_count_master_log6": number,
    "offline_count_master_log7": number,
    "offline_count_master_log8": number,
    "offline_count_master_log9": number,
    "offline_count_master_log10": number
    "roster_size_master": number,
    "roster_size_master_subs": number
    "roster_size_master_subs2": number
    "roster_size_master_subs3": number
    "roster_size_master_subs4": number
    "roster_size_master_subs5": number
    "roster_size_master_subs6": number
    "roster_size_master_subs7": number
    "roster_size_master_subs8": number
    "roster_size_master_subs9": number
    "roster_size_master_subs10": number
},
"syncthing": {
    "global": { "needBytes": bytes, "needFiles": number, "globalBytes": bytes, "globalFiles": number },
    "local": { "needBytes": bytes, "needFiles": number, "globalBytes": bytes, "globalFiles": number },
    "baseremoteagent": { "needBytes": bytes, "needFiles": number, "globalBytes": bytes, "globalFiles": number },
    "downloads": { "needBytes": bytes, "needFiles": number, "globalBytes": bytes, "globalFiles": number },
    "bootmenus": { "needBytes": bytes, "needFiles": number, "globalBytes": bytes, "globalFiles": number }
},
"mysql": {
    "uptime": seconds,
    "threads_connected": number,
    "connections_rate": percentage,
    "aborted_connects_rate": numberperminute,
    "errors_max_connections": number,
    "errors_internal": number,
    "errors_select": number,
    "errors_accept": number,
    "subquery_cache_hit_rate": number,
    "table_cache_usage" : percentage
},
"medulla_relay": {
    "deployments": { "slots_configured": number, "deployments_queued": number }
}
"medulla_main": {
    "deployments": { "current": number, "queued_at_relay": number },
    "agents": { "online": number, "offline": number, "pending_reconf": number, "pending_update": number },
    "packages": { "total": number, "total_global": number, "corrupted": number }
}
');



DROP procedure IF EXISTS `mon-systemServicesStatus`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemServicesStatus` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.ejabberd.status' ), -1 ) AS SIGNED INTEGER ) AS 'ejabberd',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.syncthing.status' ), -1 ) AS SIGNED INTEGER ) AS 'syncthing',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.apache.status' ), -1 ) AS SIGNED INTEGER ) AS 'apache',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.tomcat.status' ), -1 ) AS SIGNED INTEGER ) AS 'tomcat',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.ssh.status' ), -1 ) AS SIGNED INTEGER ) AS 'ssh',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.openldap.status' ), -1 ) AS SIGNED INTEGER ) AS 'openldap',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.mysql.status' ), -1 ) AS SIGNED INTEGER ) AS 'mysql',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.mmc-agent.status' ), -1 ) AS SIGNED INTEGER ) AS 'mmc-agent',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-agent-relay.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-agent-relay',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-package-watching.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-package-watching',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-inventory-server.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-inventory-server',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-package-server.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-package-server',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-inventory.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-inventory',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration2.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration3.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration4.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration5.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration6.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration7.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration8.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration9.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration20.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger2.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger3.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger4.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger5.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger6.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger7.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger8.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger9.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger10.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-monitoring.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-monitoring',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor2.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor3.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor4.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor5.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor6.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor7.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor8.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor9.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor10.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-reconfigurator.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-reconfigurator',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment2.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment3.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment4.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment5.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment6.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment7.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment8.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment9.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment10.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription2.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription3.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription4.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription5.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription6.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription7.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription8.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription9.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription10.status' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription10'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemServicesCPU`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemServicesCPU` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.ejabberd.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'ejabberd',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.syncthing.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'syncthing',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.apache.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'apache',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.tomcat.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'tomcat',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.ssh.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'ssh',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.openldap.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'openldap',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.mysql.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'mysql',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.mmc-agent.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'mmc-agent',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-agent-relay.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-agent-relay',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-package-watching.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-package-watching',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-inventory-server.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-inventory-server',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-package-server.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-package-server',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-inventory.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-inventory',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration2.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration3.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration4.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration5.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration6.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration7.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration8.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration9.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration10.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger2.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger3.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger4.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger5.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger6.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger7.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger8.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger9.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger10.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-monitoring.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-monitoring',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor2.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor3.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor4.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor5.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor6.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor7.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor8.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor9.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor10.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-reconfigurator.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-reconfigurator',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment2.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment3.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment4.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment5.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment6.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment7.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment8.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment9.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment10.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription2.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription3.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription4.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription5.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription6.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription7.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription8.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription9.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription10.cpu' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription10'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemServicesMemory`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemServicesMemory` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.ejabberd.memory' ), -1 ) AS SIGNED INTEGER ) AS 'ejabberd',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.syncthing.memory' ), -1 ) AS SIGNED INTEGER ) AS 'syncthing',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.apache.memory' ), -1 ) AS SIGNED INTEGER ) AS 'apache',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.tomcat.memory' ), -1 ) AS SIGNED INTEGER ) AS 'tomcat',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.ssh.memory' ), -1 ) AS SIGNED INTEGER ) AS 'ssh',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.openldap.memory' ), -1 ) AS SIGNED INTEGER ) AS 'openldap',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.mysql.memory' ), -1 ) AS SIGNED INTEGER ) AS 'mysql',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.mmc-agent.memory' ), -1 ) AS SIGNED INTEGER ) AS 'mmc-agent',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-agent-relay.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-agent-relay',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-package-watching.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-package-watching',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-inventory-server.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-inventory-server',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-package-server.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-package-server',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-inventory.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-inventory',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration2.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration3.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration4.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration5.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration6.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration7.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration8.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration9.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-registration10.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-registration10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger2.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger3.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger4.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger5.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger6.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger7.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger8.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger9.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-logger10.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-logger10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-monitoring.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-monitoring',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor2.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor3.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor4.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor5.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor6.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor7.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor8.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor9.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-assessor10.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-assessor10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-reconfigurator.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-reconfigurator',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment2.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment3.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment4.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment5.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment6.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment7.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment8.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment9.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-deployment10.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-deployment10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription2.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription3.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription4.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription5.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription6.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription7.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription8.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription9.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.services.medulla-master-substitute-subscription10.memory' ), -1 ) AS SIGNED INTEGER ) AS 'medulla-master-substitute-subscription10'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemServicesNbopenfiles`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemServicesNbopenfiles` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.services.ejabberd.nbopenfiles' ) AS SIGNED INTEGER ) AS 'ejabberd',
    CAST( JSON_EXTRACT( doc, '$.services.mysql.nbopenfiles' ) AS SIGNED INTEGER ) AS 'mysql'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemPorts`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemPorts` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.ports.ejabberd-c2s' ) AS SIGNED INTEGER ) AS 'ejabberd-c2s',
    CAST( JSON_EXTRACT( doc, '$.ports.ejabberd-s2s' ) AS SIGNED INTEGER ) AS 'ejabberd-s2s',
    CAST( JSON_EXTRACT( doc, '$.ports.syncthing' ) AS SIGNED INTEGER ) AS 'syncthing',
    CAST( JSON_EXTRACT( doc, '$.ports.syncthing-web' ) AS SIGNED INTEGER ) AS 'syncthing-web',
    CAST( JSON_EXTRACT( doc, '$.ports.syncthing-discosrv' ) AS SIGNED INTEGER ) AS 'syncthing-discosrv',
    CAST( JSON_EXTRACT( doc, '$.ports.apache' ) AS SIGNED INTEGER ) AS 'apache',
    CAST( JSON_EXTRACT( doc, '$.ports.apache-ssl' ) AS SIGNED INTEGER ) AS 'apache-ssl',
    CAST( JSON_EXTRACT( doc, '$.ports.tomcat' ) AS SIGNED INTEGER ) AS 'tomcat',
    CAST( JSON_EXTRACT( doc, '$.ports.ssh' ) AS SIGNED INTEGER ) AS 'ssh',
    CAST( JSON_EXTRACT( doc, '$.ports.mysql' ) AS SIGNED INTEGER ) AS 'mysql',
    CAST( JSON_EXTRACT( doc, '$.ports.mmc-agent' ) AS SIGNED INTEGER ) AS 'mmc-agent',
    CAST( JSON_EXTRACT( doc, '$.ports.medulla-inventory-server' ) AS SIGNED INTEGER ) AS 'medulla-inventory-server',
    CAST( JSON_EXTRACT( doc, '$.ports.medulla-package-server' ) AS SIGNED INTEGER ) AS 'medulla-package-server'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemResourcesSummary`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemResourcesSummary` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.resources.cpu' ) AS SIGNED INTEGER ) AS 'CPU',
    CAST( JSON_EXTRACT( doc, '$.resources.memory.percent' ) AS SIGNED INTEGER ) AS 'Memory',
    CAST( JSON_EXTRACT( doc, '$.resources.swap.percent' ) AS SIGNED INTEGER ) AS 'Swap',
    CAST( JSON_EXTRACT( doc, '$.resources.df_.percent' ) AS SIGNED INTEGER ) AS 'Disk free /',
    CAST( JSON_EXTRACT( doc, '$.resources.df_var.percent' ) AS SIGNED INTEGER ) AS 'Disk free /var',
    CAST( JSON_EXTRACT( doc, '$.resources.df_tmp.percent' ) AS SIGNED INTEGER ) AS 'Disk free /tmp'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemResourcesMemory`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemResourcesMemory` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.resources.memory.total' ) AS SIGNED INTEGER ) AS 'Total',
    CAST( JSON_EXTRACT( doc, '$.resources.memory.available' ) AS SIGNED INTEGER ) AS 'Available',
    CAST( JSON_EXTRACT( doc, '$.resources.memory.used' ) AS SIGNED INTEGER ) AS 'Used',
    CAST( JSON_EXTRACT( doc, '$.resources.memory.free' ) AS SIGNED INTEGER ) AS 'Free'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemResourcesSwap`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemResourcesSwap` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.resources.swap.total' ) AS SIGNED INTEGER ) AS 'Total',
    CAST( JSON_EXTRACT( doc, '$.resources.swap.used' ) AS SIGNED INTEGER ) AS 'Used',
    CAST( JSON_EXTRACT( doc, '$.resources.swap.free' ) AS SIGNED INTEGER ) AS 'Free'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemResourcesDiskfree_`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemResourcesDiskFree_` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.resources.df_.total' ) AS SIGNED INTEGER ) AS 'Total',
    CAST( JSON_EXTRACT( doc, '$.resources.df_.used' ) AS SIGNED INTEGER ) AS 'Used',
    CAST( JSON_EXTRACT( doc, '$.resources.df_.free' ) AS SIGNED INTEGER ) AS 'Free'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemResourcesDiskfree_var`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemResourcesDiskFree_var` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.resources.df_var.total' ) AS SIGNED INTEGER ) AS 'Total',
    CAST( JSON_EXTRACT( doc, '$.resources.df_var.used' ) AS SIGNED INTEGER ) AS 'Used',
    CAST( JSON_EXTRACT( doc, '$.resources.df_var.free' ) AS SIGNED INTEGER ) AS 'Free'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemResourcesDiskfree_tmp`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemResourcesDiskFree_tmp` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.resources.df_tmp.total' ) AS SIGNED INTEGER ) AS 'Total',
    CAST( JSON_EXTRACT( doc, '$.resources.df_tmp.used' ) AS SIGNED INTEGER ) AS 'Used',
    CAST( JSON_EXTRACT( doc, '$.resources.df_tmp.free' ) AS SIGNED INTEGER ) AS 'Free'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemEjabberdAccounts`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemEjabberdAccounts` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.ejabberd.registered_users' ) AS SIGNED INTEGER ) AS 'Registered users',
    CAST( JSON_EXTRACT( doc, '$.ejabberd.connected_users' ) AS SIGNED INTEGER ) AS 'Connected users'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemEjabberdOfflinemessages`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemEjabberdOfflinemessages` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_rs' ), -1 ) AS SIGNED INTEGER ) AS 'rs',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master' ), -1 ) AS SIGNED INTEGER ) AS 'master',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_inv' ), -1 ) AS SIGNED INTEGER ) AS 'master_inv',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_mon' ), -1 ) AS SIGNED INTEGER ) AS 'master_mon',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reconf' ), -1 ) AS SIGNED INTEGER ) AS 'master_reconf',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg2' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg3' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg4' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg5' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg6' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg7' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg8' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg9' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_reg10' ), -1 ) AS SIGNED INTEGER ) AS 'master_reg10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs2' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs3' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs4' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs5' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs6' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs7' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs8' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs9' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_subs10' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse2' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse3' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse4' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse5' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse6' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse7' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse8' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse9' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_asse10' ), -1 ) AS SIGNED INTEGER ) AS 'master_asse10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl2' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl3' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl4' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl5' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl6' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl7' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl8' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl9' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_depl10' ), -1 ) AS SIGNED INTEGER ) AS 'master_depl10',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log' ), -1 ) AS SIGNED INTEGER ) AS 'master_log',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log2' ), -1 ) AS SIGNED INTEGER ) AS 'master_log2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log3' ), -1 ) AS SIGNED INTEGER ) AS 'master_log3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log4' ), -1 ) AS SIGNED INTEGER ) AS 'master_log4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log5' ), -1 ) AS SIGNED INTEGER ) AS 'master_log5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log6' ), -1 ) AS SIGNED INTEGER ) AS 'master_log6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log7' ), -1 ) AS SIGNED INTEGER ) AS 'master_log7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log8' ), -1 ) AS SIGNED INTEGER ) AS 'master_log8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log9' ), -1 ) AS SIGNED INTEGER ) AS 'master_log9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.offline_count_master_log10' ), -1 ) AS SIGNED INTEGER ) AS 'master_log10'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemEjabberdRostersize`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemEjabberdRostersize` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master' ), -1 ) AS SIGNED INTEGER ) AS 'master',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs2' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs2',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs3' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs3',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs4' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs4',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs5' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs5',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs6' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs6',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs7' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs7',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs8' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs8',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs9' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs9',
    CAST( COALESCE( JSON_EXTRACT( doc, '$.ejabberd.roster_size_master_subs10' ), -1 ) AS SIGNED INTEGER ) AS 'master_subs10'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemSyncthingNeededbytes`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemSyncthingNeededbytes` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.syncthing.global.globalBytes' ) AS SIGNED INTEGER ) AS 'global total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.global.needBytes' ) AS SIGNED INTEGER ) AS 'global needed',
    CAST( JSON_EXTRACT( doc, '$.syncthing.local.globalBytes' ) AS SIGNED INTEGER ) AS 'local total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.local.needBytes' ) AS SIGNED INTEGER ) AS 'local needed',
    CAST( JSON_EXTRACT( doc, '$.syncthing.baseremoteagent.globalBytes' ) AS SIGNED INTEGER ) AS 'baseremoteagent total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.baseremoteagent.needBytes' ) AS SIGNED INTEGER ) AS 'baseremoteagent needed',
    CAST( JSON_EXTRACT( doc, '$.syncthing.downloads.globalBytes' ) AS SIGNED INTEGER ) AS 'downloads total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.downloads.needBytes' ) AS SIGNED INTEGER ) AS 'downloads needed',
    CAST( JSON_EXTRACT( doc, '$.syncthing.bootmenus.globalBytes' ) AS SIGNED INTEGER ) AS 'bootmenus total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.bootmenus.needBytes' ) AS SIGNED INTEGER ) AS 'bootmenus needed'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemSyncthingNeededfiles`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemSyncthingNeededfiles` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.syncthing.global.globalFiles' ) AS SIGNED INTEGER ) AS 'global total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.global.needFiles' ) AS SIGNED INTEGER ) AS 'global needed',
    CAST( JSON_EXTRACT( doc, '$.syncthing.local.globalFiles' ) AS SIGNED INTEGER ) AS 'local total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.local.needFiles' ) AS SIGNED INTEGER ) AS 'local needed',
    CAST( JSON_EXTRACT( doc, '$.syncthing.baseremoteagent.globalFiles' ) AS SIGNED INTEGER ) AS 'baseremoteagent total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.baseremoteagent.needFiles' ) AS SIGNED INTEGER ) AS 'baseremoteagent needed',
    CAST( JSON_EXTRACT( doc, '$.syncthing.downloads.globalFiles' ) AS SIGNED INTEGER ) AS 'downloads total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.downloads.needFiles' ) AS SIGNED INTEGER ) AS 'downloads needed',
    CAST( JSON_EXTRACT( doc, '$.syncthing.bootmenus.globalFiles' ) AS SIGNED INTEGER ) AS 'bootmenus total',
    CAST( JSON_EXTRACT( doc, '$.syncthing.bootmenus.needFiles' ) AS SIGNED INTEGER ) AS 'bootmenus needed'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemMysqlUptime`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemMysqlUptime` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.mysql.uptime' ) AS SIGNED INTEGER ) AS 'Uptime'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemMysqlThreadsconnected`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemMysqlThreadsconnected` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.mysql.threads_connected' ) AS SIGNED INTEGER ) AS 'Threads connected'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemMysqlConnectionsrate`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemMysqlConnectionsrate` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.mysql.connections_rate' ) AS SIGNED INTEGER ) AS 'Connections rate'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemMysqlAbortedconnectionsrate`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemMysqlAbortedconnectionsrate` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.mysql.aborted_connects_rate' ) AS SIGNED INTEGER ) AS 'Aborted connections rate'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemMysqlErrors`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemMysqlErrors` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.mysql.errors_max_connections' ) AS SIGNED INTEGER ) AS 'Max connections errors',
    CAST( JSON_EXTRACT( doc, '$.mysql.errors_internal' ) AS SIGNED INTEGER ) AS 'Internal errors',
    CAST( JSON_EXTRACT( doc, '$.mysql.errors_select' ) AS SIGNED INTEGER ) AS 'Select errors',
    CAST( JSON_EXTRACT( doc, '$.mysql.errors_accept' ) AS SIGNED INTEGER ) AS 'Accept errors'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemMysqlSubqueryCacheHit`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemMysqlSubqueryCacheHit` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.mysql.subquery_cache_hit_rate' ) AS SIGNED INTEGER ) AS 'Subquery cache hit'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemMysqlTableCacheUsage`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemMysqlTableCacheUsage` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.mysql.table_cache_usage' ) AS SIGNED INTEGER ) AS 'Table cache usage'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemPulserelaydeployments`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemPulserelaydeployments` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.medulla_relay.deployments.slots_configured' ) AS SIGNED INTEGER ) AS 'Slots configured',
    CAST( JSON_EXTRACT( doc, '$.medulla_relay.deployments.deployments_queued' ) AS SIGNED INTEGER ) AS 'Deployments queued'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemPulsemaindeployments`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemPulsemaindeployments` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.deployments.current' ) AS SIGNED INTEGER ) AS 'Current deployments',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.deployments.queued_at_relay' ) AS SIGNED INTEGER ) AS 'Deployments queued at relay'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemPulsemainagents`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemPulsemainagents` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.agents.online' ) AS SIGNED INTEGER ) AS 'Online',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.agents.offline' ) AS SIGNED INTEGER ) AS 'Offline',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.agents.pending_reconf' ) AS SIGNED INTEGER ) AS 'Pending reconfiguration',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.agents.pending_update' ) AS SIGNED INTEGER ) AS 'Pending update'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;


DROP procedure IF EXISTS `mon-systemPulsemainpackages`;
DELIMITER $$
USE `xmppmaster`$$
CREATE PROCEDURE `mon-systemPulsemainpackages` (IN param_hostname VARCHAR(45))
BEGIN
  SELECT
    date AS 'time',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.packages.total' ) AS SIGNED INTEGER ) AS 'Total',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.packages.total_global' ) AS SIGNED INTEGER ) AS 'Total in global',
    CAST( JSON_EXTRACT( doc, '$.medulla_main.packages.corrupted' ) AS SIGNED INTEGER ) AS 'Corrupted'
FROM
    mon_devices
INNER JOIN
    mon_machine ON xmppmaster.mon_devices.mon_machine_id = mon_machine.id
WHERE
	device_type = 'system' AND mon_machine.hostname = param_hostname
ORDER BY date;
END$$
DELIMITER ;



INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'SystemServicesStatus',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemServicesStatus`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'SystemServicesCPU',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemServicesCPU`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'SystemServicesMemory',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemServicesMemory`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'SystemServicesNbopenfiles',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemServicesNbopenfiles`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'SystemPorts',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemPorts`(\'@_hostname_@\');"}]}',
	'{}'
);



INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemResourcesSummary',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemResourcesSummary`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemResourcesMemory',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemResourcesMemory`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemResourcesSwap',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemResourcesSwap`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemResourcesDiskfree_',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemResourcesDiskfree_`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemResourcesDiskfree_var',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemResourcesDiskfree_var`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemResourcesDiskfree_tmp',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemResourcesDiskfree_tmp`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemEjabberdAccounts',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemEjabberdAccounts`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemEjabberdOfflinemessages',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemEjabberdOfflinemessages`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemEjabberdRostersize',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemEjabberdRostersize`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemSyncthingNeededbytes',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemSyncthingNeededbytes`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemSyncthingNeededfiles',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemSyncthingNeededfiles`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemMysqlUptime',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemMysqlUptime`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemMysqlThreadsconnected',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemMysqlThreadsconnected`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemMysqlConnectionsrate',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemMysqlConnectionsrate`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemMysqlErrors',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemMysqlErrors`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemMysqlSubqueryCacheHit',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemMysqlSubqueryCacheHit`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemMysqlAbortedconnectionsrate',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemMysqlAbortedconnectionsrate`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemMysqlTableCacheUsage',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemMysqlTableCacheUsage`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemPulserelaydeployments',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemPulserelaydeployments`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemPulsemaindeployments',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemPulsemaindeployments`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemPulsemainagents',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemPulsemainagents`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_panels_template
(
	name_graphe,
	type_graphe,
	template_json,
	parameters
) 
VALUES 
(
	'systemPulsemainpackages',
	'graph',
	'{"id":1,"datasource":"xmppmaster","type":"@_type_graphe_@","legend":{"show":true,"current":true,"values":true},"lines":true,"fill":0,"title":"@_name_graphe_@","xaxis":{"mode":"time","show":true},"yaxes":[{"show":true},{"show":true}],"targets":[{"format":"time_series","group":[],"metricColumn":"none","rawQuery":true,"rawSql":"call `mon-systemPulsemainpackages`(\'@_hostname_@\');"}]}',
	'{}'
);


INSERT INTO mon_rules
(
    hostname,
    os,
    type_machine,
    device_type,
    binding,
    succes_binding_cmd,
    type_event,
    comment
) 
VALUES 
(
    'spo.*',
    'Linux.*',
    'relayserver',
    'system',
    'resultbinding = True if data[\'general_status\'] != \'info\' else False',
    'True',
    'log',
    'System alert'
);

INSERT INTO mon_rules
(
    hostname,
    os,
    type_machine,
    device_type,
    binding,
    succes_binding_cmd,
    type_event,
    comment
) 
VALUES 
(
    'spo',
    'Linux.*',
    'relayserver',
    'system',
    'resultbinding = True if data[\'general_status\'] == \'info\' and data[\'ejabberd\'][\'connected_users\'] != \'0\' else False',
    'template_consolidate_online_machines_count.py',
    'script_python',
    'Consolidate online machines count'
);

INSERT INTO mon_rules
(
    hostname,
    os,
    type_machine,
    device_type,
    binding,
    succes_binding_cmd,
    type_event
) 
VALUES 
(
    'spo.*',
    'Linux.*',
    'relayserver',
    'system',
    'resultbinding = True if data[\'services\'][\'@mon_subject@\'][\'status\'] == 0 else False',
    'systemctl restart @mon_param0@',
    'cmd remote terminal'
);

INSERT INTO mon_rules
(
    hostname,
    os,
    type_machine,
    device_type,
    binding,
    succes_binding_cmd,
    type_event
) 
VALUES 
(
    'spo.*',
    'Linux.*',
    'relayserver',
    'system',
    'resultbinding = True if data[\'ports\'][\'@mon_subject@\'] == 0 else False',
    'systemctl restart @mon_param0@',
    'cmd remote terminal'
);

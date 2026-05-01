window.IAM_DASHBOARD_DATA = {
    "title":  "Identity And Access Management Dashboard",
    "generatedAt":  "2026-04-29T20:42:43.4189327-06:00",
    "generatedAtLocal":  "Wednesday, April 29 2026 20:42:43 -06:00",
    "notes":  [
                  "Live checks on April 29, 2026 showed celvpvm04314 resolving to idamhost1.vm.oracle.com and exposing the OAM/OUD control scripts directory.",
                  "Live checks on April 29, 2026 showed celvpvm04383 resolving to idm-lab1.example.com. I treated that box as the monitoring or OIG-side server for the starter build."
              ],
    "summary":  {
                    "totalTargets":  2,
                    "healthyTargets":  1,
                    "warningTargets":  1,
                    "downTargets":  0,
                    "totalApps":  4,
                    "healthyApps":  1,
                    "warningApps":  0,
                    "downApps":  3
                },
    "targets":  [
                    {
                        "name":  "OAM / OUD",
                        "role":  "Identity Stack",
                        "host":  "celvpvm04314.us.oracle.com",
                        "status":  "warning",
                        "server":  {
                                       "reachable":  true,
                                       "status":  "warning",
                                       "actualHostname":  "idamhost1.vm.oracle.com",
                                       "kernel":  "4.18.0-553.5.1.el8_10.x86_64",
                                       "os":  "Oracle Linux Server 8.10",
                                       "uptime":  {
                                                      "raw":  "02:42:19 up  4:47,  0 users,  load average: 2.90, 1.98, 1.35",
                                                      "load1":  2.9,
                                                      "load5":  1.98,
                                                      "load15":  1.35,
                                                      "cpuCount":  4,
                                                      "cpuPressure":  72.5
                                                  },
                                       "memory":  {
                                                      "totalMb":  31889,
                                                      "usedMb":  8148,
                                                      "freeMb":  8807,
                                                      "availableMb":  18188,
                                                      "usedPercent":  25.6
                                                  },
                                       "rootDisk":  {
                                                        "filesystem":  "/dev/sda3",
                                                        "size":  "26G",
                                                        "used":  "13G",
                                                        "available":  "12G",
                                                        "usedPercent":  52,
                                                        "mount":  "/"
                                                    },
                                       "refreshDisk":  {
                                                           "filesystem":  "/dev/sda2",
                                                           "size":  "51G",
                                                           "used":  "35G",
                                                           "available":  "14G",
                                                           "usedPercent":  73,
                                                           "mount":  "/refresh"
                                                       },
                                       "scriptDirectory":  "/refresh/home/auto/bin",
                                       "scripts":  [
                                                       "copy_wg_artifacts.sh",
                                                       "setdbenv",
                                                       "startAdminServer.sh",
                                                       "startAll.sh",
                                                       "startDT.sh",
                                                       "startLT.sh",
                                                       "startManagedServer.sh",
                                                       "startMT.sh",
                                                       "startOIDAdminServer.sh",
                                                       "startOIDComponents.sh",
                                                       "startOIDNodeManager.sh",
                                                       "startOUDAdminServer.sh"
                                                   ],
                                       "processes":  [
                                                         "oracle     13874 java            /refresh/home/jdk-21.0.5/bin/java --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED --add-exports=java.base/sun.security.x509=ALL-UNNAMED -Xms1028m -Xmx1028m -XX:+UseCompressedOops -server -XX:MaxTenuringThreshold=1 -XX:+UseG1GC -XX:-G1UseAdaptiveIHOP -XX:InitiatingHeapOccupancyPercent=55 -Dorg.opends.server.scriptName=start-ds org.opends.server.core.DirectoryServer --configClass org.opends.server.extensions.ConfigFileHandler --configFile /refresh/home/Instances/oudinst/OUD/config/config.ldif",
                                                         "oracle     14182 startWebLogic.s /bin/sh /refresh/home/Domains/oam_domain/startWebLogic.sh",
                                                         "oracle     14184 startWebLogic.s /bin/sh /refresh/home/Domains/oam_domain/bin/startWebLogic.sh",
                                                         "oracle     14230 java            /refresh/home/jdk-21.0.5/bin/java -Dderby.system.home=/refresh/home/Domains/oam_domain/common/db -classpath /refresh/home/Oracle/OAM/wlserver/common/derby/lib/derbyshared.jar:/refresh/home/Oracle/OAM/wlserver/common/derby/lib/derby.jar:/refresh/home/Oracle/OAM/wlserver/common/derby/lib/derbynet.jar:/refresh/home/Oracle/OAM/wlserver/common/derby/lib/derbytools.jar:/refresh/home/Oracle/OAM/wlserver/common/derby/lib/derbyoptionaltools.jar:/refresh/home/Oracle/OAM/wlserver/common/derby/lib/derbyclient.jar org.apache.derby.drda.NetworkServerControl start",
                                                         "oracle     14231 java            /refresh/home/jdk-21.0.5/bin/java -server -Xms512m -Xmx2048m -cp /refresh/home/Oracle/OAM/wlserver/server/lib/weblogic-launcher.jar -Dlaunch.use.env.classpath=true -Dweblogic.Name=AdminServer -Djava.security.policy=/refresh/home/Oracle/OAM/wlserver/server/lib/weblogic.policy -Dweblogic.ProductionModeEnabled=true -Dweblogic.ssl.AcceptKSSDemoCertsEnabled=true -Djava.system.class.loader=com.oracle.classloader.weblogic.LaunchClassLoader -Djava.protocol.handler.pkgs=oracle.mds.net.protocol|weblogic.net -Doracle.security.jps.config=/refresh/home/Domains/oam_domain/config/fmwconfig/jps-config.xml -Doracle.deployed.app.dir=/refresh/home/Domains/oam_domain/servers/AdminServer/tmp/_WL_user -Doracle.deployed.app.ext=/- -Dweblogic.alternateTypesDirectory=/refresh/home/Oracle/OAM/oracle_common/modules/oracle.ossoiap,/refresh/home/Oracle/OAM/oracle_common/modules/oracle.oamprovider,/refresh/home/Oracle/OAM/oracle_common/modules/oracle.jps,/refresh/home/Oracle/OAM/idm/oam/agent/modules/oracle.oam.wlsagent_11.1.1,/refresh/home/Oracle/OAM/idm/oam/agent/modules/oracle.oam.wlsagent_11.1.1: -Doracle.mds.filestore.preferred= -Dadf.version=14.1.2.0.0 -Dweblogic.jdbc.remoteEnabled=true -Dcommon.components.home=/refresh/home/Oracle/OAM/oracle_common -Djrf.version=12.2.2 -Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.Jdk14Logger -Ddomain.home=/refresh/home/Domains/oam_domain -Doracle.server.config.dir=/refresh/home/Domains/oam_domain/config/fmwconfig/servers/AdminServer -Doracle.domain.config.dir=/refresh/home/Domains/oam_domain/config/fmwconfig -DCONFIG_DS=jdbc/oamds -DCONFIG_HISTORY=true -DUseJSSECompatibleHttpsHandlerWLSContext=true -DOAM_POLICY_FILE=/refresh/home/Domains/oam_domain/config/fmwconfig/oam-policy.xml -DOAM_CONFIG_FILE=/refresh/home/Domains/oam_domain/config/fmwconfig/oam-config.xml -DOAM_ORACLE_HOME=/refresh/home/Oracle/OAM/idm/oam -Doracle.security.am.SERVER_INSTNCE_NAME=AdminServer -Djavax.xml.soap.SOAPConnectionFactory=weblogic.wsee.saaj.SOAPConnectionFactoryImpl -Djavax.xml.soap.MessageFactory=oracle.j2ee.ws.saaj.soap.MessageFactoryImpl -Djavax.xml.soap.SOAPFactory=oracle.j2ee.ws.saaj.soap.SOAPFactoryImpl -Djavax.management.builder.initial=weblogic.management.jmx.mbeanserver.WLSMBeanServerBuilder -javaagent:/refresh/home/Oracle/OAM/wlserver/server/lib/debugpatch-agent.jar -da -Dwls.home=/refresh/home/Oracle/OAM/wlserver/server -Dweblogic.home=/refresh/home/Oracle/OAM/wlserver/server -Djavax.management.builder.initial=weblogic.management.jmx.mbeanserver.WLSMBeanServerBuilder -Doracle.idm.ipf.home=/refresh/home/Oracle/OAM/idm//modules/oracle.idm.ipf_14.1.2 -Dem.oracle.home=/refresh/home/Oracle/OAM/em -DINSTANCE_HOME=/refresh/home/Domains/oam_domain -Djava.awt.headless=true -Doracle.sysman.util.logging.mode=dual_mode -Djava.util.logging.manager=oracle.core.ojdl.logging.ODLLogManager weblogic.Server",
                                                         "oracle     15160 startManagedWeb /bin/sh /refresh/home/Domains/oam_domain/bin/startManagedWebLogic.sh oam_server1 t3://idamhost1.vm.oracle.com:7001",
                                                         "oracle     15162 startWebLogic.s /bin/sh /refresh/home/Domains/oam_domain/bin/startWebLogic.sh nodebug noderby",
                                                         "oracle     15207 java            /refresh/home/jdk-21.0.5/bin/java -server -Xms256m -Xmx2048m -cp /refresh/home/Oracle/OAM/wlserver/server/lib/weblogic-launcher.jar -Dlaunch.use.env.classpath=true -Dweblogic.Name=oam_server1 -Djava.security.policy=/refresh/home/Oracle/OAM/wlserver/server/lib/weblogic.policy -Dweblogic.ProductionModeEnabled=true -Dweblogic.ssl.AcceptKSSDemoCertsEnabled=true -Djava.system.class.loader=com.oracle.classloader.weblogic.LaunchClassLoader -Djava.protocol.handler.pkgs=oracle.mds.net.protocol|weblogic.net -Doracle.security.jps.config=/refresh/home/Domains/oam_domain/config/fmwconfig/jps-config.xml -Doracle.deployed.app.dir=/refresh/home/Domains/oam_domain/servers/oam_server1/tmp/_WL_user -Doracle.deployed.app.ext=/- -Dweblogic.alternateTypesDirectory=/refresh/home/Oracle/OAM/oracle_common/modules/oracle.ossoiap,/refresh/home/Oracle/OAM/oracle_common/modules/oracle.oamprovider,/refresh/home/Oracle/OAM/oracle_common/modules/oracle.jps,/refresh/home/Oracle/OAM/idm/oam/agent/modules/oracle.oam.wlsagent_11.1.1,/refresh/home/Oracle/OAM/idm/oam/agent/modules/oracle.oam.wlsagent_11.1.1: -Doracle.mds.filestore.preferred= -Dadf.version=14.1.2.0.0 -Dweblogic.jdbc.remoteEnabled=true -Dcommon.components.home=/refresh/home/Oracle/OAM/oracle_common -Djrf.version=12.2.2 -Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.Jdk14Logger -Ddomain.home=/refresh/home/Domains/oam_domain -Doracle.server.config.dir=/refresh/home/Domains/oam_domain/config/fmwconfig/servers/oam_server1 -Doracle.domain.config.dir=/refresh/home/Domains/oam_domain/config/fmwconfig -DCONFIG_DS=jdbc/oamds -DCONFIG_HISTORY=true -DUseJSSECompatibleHttpsHandlerWLSContext=true -DOAM_POLICY_FILE=/refresh/home/Domains/oam_domain/config/fmwconfig/oam-policy.xml -DOAM_CONFIG_FILE=/refresh/home/Domains/oam_domain/config/fmwconfig/oam-config.xml -DOAM_ORACLE_HOME=/refresh/home/Oracle/OAM/idm/oam -Doracle.security.am.SERVER_INSTNCE_NAME=oam_server1 -Djavax.xml.soap.SOAPConnectionFactory=weblogic.wsee.saaj.SOAPConnectionFactoryImpl -Djavax.xml.soap.MessageFactory=oracle.j2ee.ws.saaj.soap.MessageFactoryImpl -Djavax.xml.soap.SOAPFactory=oracle.j2ee.ws.saaj.soap.SOAPFactoryImpl -Djavax.management.builder.initial=weblogic.management.jmx.mbeanserver.WLSMBeanServerBuilder -javaagent:/refresh/home/Oracle/OAM/wlserver/server/lib/debugpatch-agent.jar -da -Dwls.home=/refresh/home/Oracle/OAM/wlserver/server -Dweblogic.home=/refresh/home/Oracle/OAM/wlserver/server -Djavax.management.builder.initial=weblogic.management.jmx.mbeanserver.WLSMBeanServerBuilder -Doracle.idm.ipf.home=/refresh/home/Oracle/OAM/idm//modules/oracle.idm.ipf_14.1.2 -Dem.oracle.home=/refresh/home/Oracle/OAM/em -Dweblogic.management.server=t3://idamhost1.vm.oracle.com:7001 -Djava.util.logging.manager=oracle.core.ojdl.logging.ODLLogManager weblogic.Server",
                                                         "oracle     15592 startNodeManage /bin/sh /refresh/home/Oracle/OHS/wlserver/server/bin/startNodeManager.sh",
                                                         "oracle     15694 java            /refresh/home/jdk-21.0.5/bin/java -server -Xms32m -Xmx200m -Djdk.tls.ephemeralDHKeySize=2048 -Dcoherence.home=/refresh/home/Oracle/OHS/wlserver/../coherence -Dbea.home=/refresh/home/Oracle/OHS/wlserver/.. -Dohs.product.home=/refresh/home/Oracle/OHS/ohs -Doracle.security.jps.config=/refresh/home/Domains/webtier_domain/config/fmwconfig/jps-config-jse.xml -Dcommon.components.home=/refresh/home/Oracle/OHS/oracle_common -Dopss.version=12.2.1.3 -Dweblogic.RootDirectory=/refresh/home/Domains/webtier_domain -Djava.system.class.loader=com.oracle.classloader.weblogic.LaunchClassLoader -Djava.security.policy=/refresh/home/Oracle/OHS/wlserver/server/lib/weblogic.policy -Dweblogic.nodemanager.JavaHome=/refresh/home/jdk-21.0.5 weblogic.NodeManager -v"
                                                     ]
                                   },
                        "appChecks":  [
                                          {
                                              "name":  "OAM Console",
                                              "url":  "http://localhost:7001/oamconsole",
                                              "status":  "healthy",
                                              "statusText":  "Reachable",
                                              "httpCode":  200,
                                              "responseTimeMs":  45
                                          },
                                          {
                                              "name":  "OUDSM",
                                              "url":  "http://localhost:7101/oudsm",
                                              "status":  "down",
                                              "statusText":  "Connection failed or service is not listening",
                                              "httpCode":  0,
                                              "responseTimeMs":  3
                                          },
                                          {
                                              "name":  "OAM Access",
                                              "url":  "http://localhost:14150/access",
                                              "status":  "down",
                                              "statusText":  "Connection failed or service is not listening",
                                              "httpCode":  0,
                                              "responseTimeMs":  3
                                          },
                                          {
                                              "name":  "Fusion Middleware EM",
                                              "url":  "http://localhost:7201/em",
                                              "status":  "down",
                                              "statusText":  "Connection failed or service is not listening",
                                              "httpCode":  0,
                                              "responseTimeMs":  3
                                          }
                                      ]
                    },
                    {
                        "name":  "Monitoring / OIG",
                        "role":  "Monitoring Server",
                        "host":  "celvpvm04383.us.oracle.com",
                        "status":  "healthy",
                        "server":  {
                                       "reachable":  true,
                                       "status":  "healthy",
                                       "actualHostname":  "idm-lab1.example.com",
                                       "kernel":  "5.15.0-306.177.4.el8uek.x86_64",
                                       "os":  "Oracle Linux Server 8.10",
                                       "uptime":  {
                                                      "raw":  "02:42:37 up 11 days, 21:52,  0 users,  load average: 0.27, 0.15, 0.06",
                                                      "load1":  0.27,
                                                      "load5":  0.15,
                                                      "load15":  0.06,
                                                      "cpuCount":  4,
                                                      "cpuPressure":  6.8
                                                  },
                                       "memory":  {
                                                      "totalMb":  23745,
                                                      "usedMb":  2297,
                                                      "freeMb":  12180,
                                                      "availableMb":  17175,
                                                      "usedPercent":  9.7
                                                  },
                                       "rootDisk":  {
                                                        "filesystem":  "/dev/sda3",
                                                        "size":  "16G",
                                                        "used":  "12G",
                                                        "available":  "2.9G",
                                                        "usedPercent":  81,
                                                        "mount":  "/"
                                                    },
                                       "refreshDisk":  null,
                                       "scriptDirectory":  "/refresh/home/auto/bin",
                                       "scripts":  [

                                                   ],
                                       "processes":  [
                                                         "root     1153538 grep            grep -E -i java|oig|grafana|prometheus|node_exporter"
                                                     ]
                                   },
                        "appChecks":  [

                                      ]
                    }
                ]
};

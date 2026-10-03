Define adapter as a device with zpr.adapter.cn.

Define NextCloud as a service with device.zpr.adapter.cn:'nc.zpr.org'.

Define RfcDB as a service with device.zpr.adapter.cn:'web.zpr.org'.

Define NextCloudPing as a service with device.zpr.adapter.cn:'nc.zpr.org'.

Define RfcDBPing as a service with device.zpr.adapter.cn:'web.zpr.org'.

# Allow any valid adapter to access our two services.

service NextCloud as json {"service_class":"NextCloud"}.
  allow zpr.adapter.cn: adapter.

service RfcDB as json {"service_class":"RfcDB"}.
  allow zpr.adapter.cn: adapter.

# Allow any valid adapter to ping the web and nextcloud.

service NextCloudPing as json {"service_class":"NextCloudPing"}.
  allow zpr.adapter.cn: adapter.

service RfcDBPing as json {"service_class":"RfcDBPing"}.
  allow zpr.adapter.cn: adapter.

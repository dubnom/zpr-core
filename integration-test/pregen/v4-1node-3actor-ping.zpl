# three adapters: they can ping each other
# One node, one visa service: they can ping each other

define adapter as a device with zpr.adapter.cn.

define A1 as adapter with zpr.adapter.cn:adapter1.
define A2 as adapter with zpr.adapter.cn:adapter2.
define A3 as adapter with zpr.adapter.cn:adapter3.
define Node as adapter with zpr.adapter.cn:node.
define Vs as adapter with zpr.adapter.cn:'vs.zpr'.

define A1Svc as a service with device.zpr.adapter.cn:adapter1.
define A2Svc as a service with device.zpr.adapter.cn:adapter2.
define A3Svc as a service with device.zpr.adapter.cn:adapter3.
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableNode as a service with device.zpr.adapter.cn:node.

# Admin access to VS
define VsAdmin as a device with zpr.adapter.cn:'client.zpr.org'.

service A1Svc as json {"service_class":"A1Svc"}.
  allow A2.
  allow A3.

service A2Svc as json {"service_class":"A2Svc"}.
  allow A1.
  allow A3.

service A3Svc as json {"service_class":"A3Svc"}.
  allow A1.
  allow A2.

service PingableVs as json {"service_class":"PingableVs"}.
  allow Node.

service PingableNode as json {"service_class":"PingableNode"}.
  allow Vs.

provide VisaService at visa-admin.svc.zpr over TCP 443.
  allow VsAdmin.

package expo.modules.networkscanner

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.BufferedReader
import java.io.FileReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class NetworkScannerModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("NetworkScanner")

        AsyncFunction("readArpTable") {
            val entries = mutableListOf<Map<String, String>>()
            try {
                val reader = BufferedReader(FileReader("/proc/net/arp"))
                reader.readLine() // skip header
                var line = reader.readLine()
                while (line != null) {
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size >= 4) {
                        val mac = parts[3].uppercase()
                        if (mac != "00:00:00:00:00:00" && mac != "INCOMPLETE" && mac.contains(":")) {
                            entries.add(mapOf("ip" to parts[0], "mac" to mac))
                        }
                    }
                    line = reader.readLine()
                }
                reader.close()
            } catch (_: Exception) {}
            entries
        }

        AsyncFunction("getWifiInfo") {
            val context = appContext.reactContext
                ?: throw Exception("React context not available")
            val wifiManager = context.applicationContext
                .getSystemService(Context.WIFI_SERVICE) as WifiManager
            val connInfo = wifiManager.connectionInfo
            val dhcp = wifiManager.dhcpInfo
            mapOf(
                "gateway" to intToIp(dhcp.gateway),
                "localIp" to intToIp(dhcp.ipAddress),
                "netmask" to intToIp(dhcp.netmask),
                "ssid" to (connInfo.ssid?.removeSurrounding("\"") ?: ""),
                "bssid" to (connInfo.bssid ?: "")
            )
        }

        AsyncFunction("scanPorts") { host: String, ports: List<Int>, timeoutMs: Int ->
            val executor = Executors.newFixedThreadPool(minOf(ports.size, 30))
            val futures = ports.map { port ->
                executor.submit<Map<String, Any>> {
                    try {
                        val socket = Socket()
                        socket.connect(InetSocketAddress(host, port), timeoutMs)
                        val banner = try {
                            socket.soTimeout = 2000
                            val buffer = ByteArray(1024)
                            val input = socket.getInputStream()
                            if (input.available() > 0 || run { Thread.sleep(500); input.available() > 0 }) {
                                val read = input.read(buffer)
                                if (read > 0) String(buffer, 0, read, Charsets.UTF_8) else ""
                            } else ""
                        } catch (_: Exception) { "" }
                        socket.close()
                        mapOf("port" to port, "open" to true, "banner" to banner)
                    } catch (_: Exception) {
                        mapOf("port" to port, "open" to false, "banner" to "")
                    }
                }
            }
            val results = futures.mapNotNull { f ->
                try {
                    val result = f.get(timeoutMs.toLong() + 3000, TimeUnit.MILLISECONDS)
                    if (result["open"] as Boolean) result else null
                } catch (_: Exception) { null }
            }
            executor.shutdown()
            executor.awaitTermination(5, TimeUnit.SECONDS)
            results
        }

        AsyncFunction("probeRtsp") { host: String, port: Int ->
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress(host, port), 3000)
                socket.soTimeout = 3000
                val request = "OPTIONS rtsp://$host:$port RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                socket.getOutputStream().write(request.toByteArray())
                socket.getOutputStream().flush()
                Thread.sleep(500)
                val buffer = ByteArray(2048)
                val read = socket.getInputStream().read(buffer)
                val response = if (read > 0) String(buffer, 0, read, Charsets.UTF_8) else ""
                socket.close()
                mapOf("success" to true, "response" to response)
            } catch (_: Exception) {
                mapOf("success" to false, "response" to "")
            }
        }

        AsyncFunction("discoverHosts") { baseIp: String, startHost: Int, endHost: Int, port: Int, timeoutMs: Int ->
            val executor = Executors.newFixedThreadPool(50)
            val range = startHost..minOf(endHost, 254)
            val futures = range.map { hostNum ->
                val ip = "$baseIp.$hostNum"
                executor.submit<String?> {
                    try {
                        val socket = Socket()
                        socket.connect(InetSocketAddress(ip, port), timeoutMs)
                        socket.close()
                        return@submit ip
                    } catch (_: Exception) {}
                    try {
                        val addr = InetAddress.getByName(ip)
                        if (addr.isReachable(timeoutMs)) return@submit ip
                    } catch (_: Exception) {}
                    null
                }
            }
            val results = futures.mapNotNull { f ->
                try { f.get((timeoutMs + 1000).toLong(), TimeUnit.MILLISECONDS) }
                catch (_: Exception) { null }
            }
            executor.shutdown()
            executor.awaitTermination(10, TimeUnit.SECONDS)
            results
        }

        AsyncFunction("pingHost") { host: String, timeoutMs: Int ->
            try {
                InetAddress.getByName(host).isReachable(timeoutMs)
            } catch (_: Exception) { false }
        }

        AsyncFunction("discoverMdnsServices") { serviceTypes: List<String>, timeoutMs: Int ->
            val context = appContext.reactContext
                ?: throw Exception("React context not available")
            val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
            val discovered = mutableListOf<Map<String, String>>()
            val listeners = mutableListOf<NsdManager.DiscoveryListener>()
            val latch = CountDownLatch(1)

            for (serviceType in serviceTypes) {
                val listener = object : NsdManager.DiscoveryListener {
                    override fun onDiscoveryStarted(regType: String) {}
                    override fun onDiscoveryStopped(serviceType: String) {}
                    override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
                    override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}

                    override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                        // Resolve service to get IP
                        try {
                            nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
                                override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                                    synchronized(discovered) {
                                        discovered.add(mapOf(
                                            "name" to (serviceInfo.serviceName ?: ""),
                                            "serviceType" to (serviceInfo.serviceType ?: ""),
                                            "ip" to (serviceInfo.host?.hostAddress ?: ""),
                                            "port" to (serviceInfo.port.toString())
                                        ))
                                    }
                                }
                            })
                        } catch (_: Exception) {}
                    }

                    override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
                }
                listeners.add(listener)
                try {
                    nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
                } catch (_: Exception) {}
            }

            // Wait for discovery period
            latch.await(timeoutMs.toLong(), TimeUnit.MILLISECONDS)

            // Stop all discoveries
            for (listener in listeners) {
                try { nsdManager.stopServiceDiscovery(listener) }
                catch (_: Exception) {}
            }

            // Brief additional wait for pending resolves
            Thread.sleep(1000)

            synchronized(discovered) { discovered.toList() }
        }
    }

    private fun intToIp(ip: Int): String {
        return "${ip and 0xFF}.${ip shr 8 and 0xFF}.${ip shr 16 and 0xFF}.${ip shr 24 and 0xFF}"
    }
}

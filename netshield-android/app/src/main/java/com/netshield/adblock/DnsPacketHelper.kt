package com.netshield.adblock

object DnsPacketHelper {

    data class ParsedUdpDns(
        val ipVersion: Int, // 4 hoặc 6
        val srcIp: ByteArray, // 4 byte (IPv4) hoặc 16 byte (IPv6)
        val dstIp: ByteArray, // 4 byte (IPv4) hoặc 16 byte (IPv6)
        val srcPort: Int,
        val dstPort: Int,
        val dnsPayload: ByteArray,
        val domain: String,
        val qType: Int
    )

    fun parseUdpDns(packet: ByteArray, length: Int): ParsedUdpDns? {
        if (length < 28) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        return when (version) {
            4 -> parseIpv4UdpDns(packet, length)
            6 -> parseIpv6UdpDns(packet, length)
            else -> null
        }
    }

    private fun parseIpv4UdpDns(packet: ByteArray, length: Int): ParsedUdpDns? {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null // Chỉ xử lý UDP

        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        if (dstPort != 53) return null

        val udpLen = ((packet[ihl + 4].toInt() and 0xFF) shl 8) or (packet[ihl + 5].toInt() and 0xFF)
        val dnsStart = ihl + 8
        val dnsLen = minOf(udpLen - 8, length - dnsStart)
        if (dnsLen < 12) return null

        val dnsPayload = packet.copyOfRange(dnsStart, dnsStart + dnsLen)
        val (domain, qType) = extractQueryInfo(dnsPayload) ?: return null

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)

        return ParsedUdpDns(4, srcIp, dstIp, srcPort, dstPort, dnsPayload, domain, qType)
    }

    private fun parseIpv6UdpDns(packet: ByteArray, length: Int): ParsedUdpDns? {
        if (length < 48) return null
        val nextHeader = packet[6].toInt() and 0xFF
        if (nextHeader != 17) return null // Chỉ xử lý UDP trực tiếp

        val ipLen = 40
        val srcPort = ((packet[ipLen].toInt() and 0xFF) shl 8) or (packet[ipLen + 1].toInt() and 0xFF)
        val dstPort = ((packet[ipLen + 2].toInt() and 0xFF) shl 8) or (packet[ipLen + 3].toInt() and 0xFF)
        if (dstPort != 53) return null

        val udpLen = ((packet[ipLen + 4].toInt() and 0xFF) shl 8) or (packet[ipLen + 5].toInt() and 0xFF)
        val dnsStart = ipLen + 8
        val dnsLen = minOf(udpLen - 8, length - dnsStart)
        if (dnsLen < 12) return null

        val dnsPayload = packet.copyOfRange(dnsStart, dnsStart + dnsLen)
        val (domain, qType) = extractQueryInfo(dnsPayload) ?: return null

        val srcIp = packet.copyOfRange(8, 24)
        val dstIp = packet.copyOfRange(24, 40)

        return ParsedUdpDns(6, srcIp, dstIp, srcPort, dstPort, dnsPayload, domain, qType)
    }

    fun extractQueryInfo(dns: ByteArray): Pair<String, Int>? {
        if (dns.size < 13) return null
        var idx = 12
        val sb = StringBuilder()
        var steps = 0

        while (idx < dns.size && steps < 64) {
            steps++
            val len = dns[idx].toInt() and 0xFF
            if (len == 0) {
                idx++
                break
            }
            // Bỏ qua pointer compression nếu bất thường ở question
            if ((len and 0xC0) == 0xC0) return null
            idx++
            if (idx + len > dns.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until len) {
                sb.append(dns[idx + i].toInt().toChar())
            }
            idx += len
        }
        if (sb.isEmpty()) return null
        val qType = if (idx + 1 < dns.size) {
            ((dns[idx].toInt() and 0xFF) shl 8) or (dns[idx + 1].toInt() and 0xFF)
        } else {
            1 // Default A
        }
        return sb.toString().lowercase() to qType
    }

    /**
     * Tạo gói phản hồi chặn chuẩn tiết kiệm pin (TTL = 3600s để Android netd cache 1 giờ, tránh đánh thức VPN):
     * - A (IPv4): trả 0.0.0.0 (TTL 3600s)
     * - AAAA (IPv6): trả :: (TTL 3600s)
     * - Loại khác (HTTPS/SVCB/TXT...): trả NOERROR + SOA (TTL 3600s) theo RFC 2308
     */
    fun buildBlockedResponse(query: ByteArray, qType: Int): ByteArray {
        if (query.size < 12) return query
        val questionEnd = findQuestionEnd(query)
        val rd = query[2].toInt() and 0x01

        if (qType == 1 || qType == 28) {
            val rdataLen = if (qType == 1) 4 else 16
            val answerLen = 12 + rdataLen
            val resp = ByteArray(questionEnd + answerLen)
            System.arraycopy(query, 0, resp, 0, questionEnd)

            // Header: QR=1, RD giữ nguyên, RA=1, RCODE=0 (NOERROR), QD=1, AN=1
            resp[2] = (0x80 or rd).toByte()
            resp[3] = 0x80.toByte()
            resp[4] = 0x00; resp[5] = 0x01
            resp[6] = 0x00; resp[7] = 0x01
            resp[8] = 0x00; resp[9] = 0x00
            resp[10] = 0x00; resp[11] = 0x00

            var p = questionEnd
            resp[p++] = 0xC0.toByte(); resp[p++] = 0x0C.toByte() // Pointer tới QNAME ở offset 12
            resp[p++] = ((qType ushr 8) and 0xFF).toByte(); resp[p++] = (qType and 0xFF).toByte()
            resp[p++] = 0x00; resp[p++] = 0x01 // Class IN
            // TTL = 3600 giây (0x00000E10)
            resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 0x0E; resp[p++] = 0x10
            // RDLENGTH = 4 hoặc 16 (RDATA mặc định toàn 0 = 0.0.0.0 hoặc ::)
            resp[p++] = 0x00; resp[p] = rdataLen.toByte()
            return resp
        }

        // Các qType khác (HTTPS=65, SVCB=64...): NOERROR + SOA authority (33 bytes, TTL 3600s)
        val soaLen = 33
        val resp = ByteArray(questionEnd + soaLen)
        System.arraycopy(query, 0, resp, 0, questionEnd)

        resp[2] = (0x80 or rd).toByte()
        resp[3] = 0x80.toByte()
        resp[4] = 0x00; resp[5] = 0x01
        resp[6] = 0x00; resp[7] = 0x00
        resp[8] = 0x00; resp[9] = 0x01 // NSCOUNT = 1 (SOA)
        resp[10] = 0x00; resp[11] = 0x00

        var p = questionEnd
        resp[p++] = 0x00 // Root name "."
        resp[p++] = 0x00; resp[p++] = 0x06 // TYPE = SOA
        resp[p++] = 0x00; resp[p++] = 0x01 // CLASS = IN
        resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 0x0E; resp[p++] = 0x10 // TTL = 3600
        resp[p++] = 0x00; resp[p++] = 0x16 // RDLENGTH = 22
        resp[p++] = 0x00 // MNAME = "."
        resp[p++] = 0x00 // RNAME = "."
        resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 0x01 // SERIAL = 1
        // REFRESH, RETRY, EXPIRE, MINIMUM = 3600
        repeat(4) {
            resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 0x0E; resp[p++] = 0x10
        }
        return resp
    }

    /**
     * Tạo gói phản hồi DNS SERVFAIL (RCODE = 2) khi mất mạng/upstream lỗi để app không bị treo chờ
     */
    fun buildServFailResponse(query: ByteArray): ByteArray = buildErrorResponse(query, 2)

    private fun findQuestionEnd(query: ByteArray): Int {
        var idx = 12
        while (idx < query.size) {
            val len = query[idx].toInt() and 0xFF
            idx++
            if (len == 0) break
            if ((len and 0xC0) == 0xC0) {
                idx++
                break
            }
            idx += len
        }
        return minOf(idx + 4, query.size)
    }

    private fun buildErrorResponse(query: ByteArray, rcode: Int): ByteArray {
        if (query.size < 12) return query
        val questionEnd = findQuestionEnd(query)
        val resp = query.copyOfRange(0, questionEnd)

        // Flags: QR=1, RD giữ nguyên từ query, RA=1, RCODE=rcode
        val rd = query[2].toInt() and 0x01
        resp[2] = (0x80 or rd).toByte()
        resp[3] = (0x80 or (rcode and 0x0F)).toByte()
        // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        resp[4] = 0x00; resp[5] = 0x01
        resp[6] = 0x00; resp[7] = 0x00
        resp[8] = 0x00; resp[9] = 0x00
        resp[10] = 0x00; resp[11] = 0x00
        return resp
    }

    /**
     * Đóng gói ngược DNS response vào gói IPv4 hoặc IPv6 + UDP gửi trả về giao diện TUN
     */
    fun wrapUdpResponse(req: ParsedUdpDns, dnsResponse: ByteArray): ByteArray {
        return if (req.ipVersion == 6) {
            wrapIpv6UdpResponse(req, dnsResponse)
        } else {
            wrapIpv4UdpResponse(req, dnsResponse)
        }
    }

    private fun wrapIpv4UdpResponse(req: ParsedUdpDns, dnsResponse: ByteArray): ByteArray {
        val ipLen = 20
        val udpLen = 8 + dnsResponse.size
        val totalLen = ipLen + udpLen
        val out = ByteArray(totalLen)

        // IPv4 Header
        out[0] = 0x45.toByte() // Version 4, IHL 5 (20 bytes)
        out[1] = 0x00
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[4] = 0x00; out[5] = 0x00 // Identification
        out[6] = 0x40.toByte(); out[7] = 0x00 // Don't Fragment
        out[8] = 64.toByte() // TTL
        out[9] = 17.toByte() // UDP
        out[10] = 0x00; out[11] = 0x00 // Checksum placeholder

        // Đảo Src IP <-> Dst IP
        System.arraycopy(req.dstIp, 0, out, 12, 4)
        System.arraycopy(req.srcIp, 0, out, 16, 4)

        // Tính IPv4 Header Checksum
        val checksum = computeIpv4Checksum(out, ipLen)
        out[10] = ((checksum ushr 8) and 0xFF).toByte()
        out[11] = (checksum and 0xFF).toByte()

        // UDP Header (đảo Src Port <-> Dst Port)
        out[20] = ((req.dstPort ushr 8) and 0xFF).toByte()
        out[21] = (req.dstPort and 0xFF).toByte()
        out[22] = ((req.srcPort ushr 8) and 0xFF).toByte()
        out[23] = (req.srcPort and 0xFF).toByte()
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0x00; out[27] = 0x00

        System.arraycopy(dnsResponse, 0, out, 28, dnsResponse.size)

        // Tính UDP Checksum chuẩn (IPv4 pseudo-header + UDP header + payload)
        val udpChecksum = computeIpv4UdpChecksum(out, ipLen, udpLen)
        out[26] = ((udpChecksum ushr 8) and 0xFF).toByte()
        out[27] = (udpChecksum and 0xFF).toByte()
        return out
    }

    private fun wrapIpv6UdpResponse(req: ParsedUdpDns, dnsResponse: ByteArray): ByteArray {
        val ipLen = 40
        val udpLen = 8 + dnsResponse.size
        val totalLen = ipLen + udpLen
        val out = ByteArray(totalLen)

        // IPv6 Header
        out[0] = 0x60.toByte() // Version 6
        out[1] = 0x00; out[2] = 0x00; out[3] = 0x00
        out[4] = ((udpLen ushr 8) and 0xFF).toByte() // Payload Length
        out[5] = (udpLen and 0xFF).toByte()
        out[6] = 17.toByte() // Next Header = UDP
        out[7] = 64.toByte() // Hop Limit

        // Đảo Src IP <-> Dst IP (16 bytes mỗi địa chỉ)
        System.arraycopy(req.dstIp, 0, out, 8, 16)
        System.arraycopy(req.srcIp, 0, out, 24, 16)

        // UDP Header
        out[40] = ((req.dstPort ushr 8) and 0xFF).toByte()
        out[41] = (req.dstPort and 0xFF).toByte()
        out[42] = ((req.srcPort ushr 8) and 0xFF).toByte()
        out[43] = (req.srcPort and 0xFF).toByte()
        out[44] = ((udpLen ushr 8) and 0xFF).toByte()
        out[45] = (udpLen and 0xFF).toByte()
        out[46] = 0x00; out[47] = 0x00

        System.arraycopy(dnsResponse, 0, out, 48, dnsResponse.size)

        // Tính UDP Checksum chuẩn IPv6 (bắt buộc trong IPv6)
        val udpChecksum = computeIpv6UdpChecksum(out, ipLen, udpLen)
        out[46] = ((udpChecksum ushr 8) and 0xFF).toByte()
        out[47] = (udpChecksum and 0xFF).toByte()
        return out
    }

    private fun computeIpv4UdpChecksum(packet: ByteArray, ipLen: Int, udpLen: Int): Int {
        var sum = 0
        // Pseudo-header: Src IP (4 bytes) + Dst IP (4 bytes) + Protocol (17) + UDP Length
        for (i in 12 until 20 step 2) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
        }
        sum += 17 // Protocol UDP
        sum += udpLen
        return finalizeUdpChecksum(packet, ipLen, udpLen, sum)
    }

    private fun computeIpv6UdpChecksum(packet: ByteArray, ipLen: Int, udpLen: Int): Int {
        var sum = 0
        // Pseudo-header: Src IP (16 bytes) + Dst IP (16 bytes) + UDP Length (32-bit) + Next Header (17)
        for (i in 8 until 40 step 2) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
        }
        sum += (udpLen ushr 16) and 0xFFFF
        sum += udpLen and 0xFFFF
        sum += 17 // Next Header UDP
        return finalizeUdpChecksum(packet, ipLen, udpLen, sum)
    }

    private fun finalizeUdpChecksum(packet: ByteArray, ipLen: Int, udpLen: Int, initialSum: Int): Int {
        var sum = initialSum
        var i = ipLen
        val end = ipLen + udpLen
        while (i + 1 < end) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val res = sum.inv() and 0xFFFF
        return if (res == 0) 0xFFFF else res
    }

    private fun computeIpv4Checksum(buf: ByteArray, length: Int): Int {
        var sum = 0
        var i = 0
        while (i < length) {
            val word = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }
}

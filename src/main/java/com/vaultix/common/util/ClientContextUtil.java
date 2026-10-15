package com.vaultix.common.util;

import com.vaultix.common.constant.CommonHeaders;

import jakarta.servlet.http.HttpServletRequest;

public final class ClientContextUtil {

    public static final String UNKNOWN = "Unknown";

    private ClientContextUtil() {
    }

    /**
     * Extracts the client IP from the request. Prefers the trusted
     * 'X-Client-IP' header set by the API Gateway. Falls back to the remote
     * address (e.g., during direct local development), or 'Unknown' if
     * unavailable.
     *
     * @param request the HTTP servlet request
     * @return the extracted client IP address, or 'Unknown' if unavailable or
     * request is null
     */
    public static String getClientIp(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }

        String clientIp = request.getHeader(CommonHeaders.X_CLIENT_IP);
        if (clientIp != null && !clientIp.isBlank()) {
            int commaIndex = clientIp.indexOf(',');
            String ip = (commaIndex != -1) ? clientIp.substring(0, commaIndex).trim() : clientIp.trim();
            return !ip.isBlank() ? ip : UNKNOWN;
        }

        String remoteAddr = request.getRemoteAddr();
        return (remoteAddr != null && !remoteAddr.isBlank()) ? remoteAddr.trim() : UNKNOWN;
    }

    /**
     * Extracts the parsed device info from the 'X-Device-Info' header set by
     * the API Gateway.
     *
     * @param request the HTTP servlet request
     * @return the extracted device info, or 'Unknown' if header is absent/blank
     * or request is null
     */
    public static String getDeviceInfo(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }

        String deviceInfo = request.getHeader(CommonHeaders.X_DEVICE_INFO);
        return (deviceInfo != null && !deviceInfo.isBlank()) ? deviceInfo.trim() : UNKNOWN;
    }

    /**
     * Extracts the resolved device location from the 'X-Device-Location' header
     * set by the API Gateway.
     *
     * @param request the HTTP servlet request
     * @return the extracted device location, or 'Unknown' if header is
     * absent/blank or request is null
     */
    public static String getDeviceLocation(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }

        String location = request.getHeader(CommonHeaders.X_DEVICE_LOCATION);
        return (location != null && !location.isBlank()) ? location.trim() : UNKNOWN;
    }

    /**
     * Extracts all client context values (IP, device info, location) in a
     * single pass.
     *
     * @param request the HTTP servlet request
     * @return a ClientContext record populated with resolved values or
     * 'Unknown'
     */
    public static ClientContext extract(HttpServletRequest request) {
        return new ClientContext(getClientIp(request), getDeviceInfo(request), getDeviceLocation(request));
    }

    /**
     * Strongly typed record representing the client execution context forwarded
     * by the gateway.
     */
    public record ClientContext(String ip, String deviceInfo, String location) {

    }
}

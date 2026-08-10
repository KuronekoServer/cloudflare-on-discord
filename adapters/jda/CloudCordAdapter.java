package org.cloudcord.adapter;

import java.net.URI;
import java.util.Objects;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.requests.RestConfig;

/** Endpoint adapter pinned to JDA 6.4.2. */
public final class CloudCordAdapter {
    private CloudCordAdapter() {}

    public static JDABuilder configure(JDABuilder builder, String origin) {
        Objects.requireNonNull(builder, "builder");
        URI uri = URI.create(Objects.requireNonNull(origin, "origin"));
        boolean localhost = "localhost".equals(uri.getHost())
            || "127.0.0.1".equals(uri.getHost())
            || "::1".equals(uri.getHost());
        if (!"https".equalsIgnoreCase(uri.getScheme())
            && !(localhost && "http".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalArgumentException("CloudCord Bot API origin must use HTTPS");
        }
        if (uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("Origin must not contain credentials or a query");
        }
        String normalized = origin.replaceAll("/+$", "");
        return builder.setRestConfig(new RestConfig().setBaseUrl(normalized + "/api/v10/"));
    }
}

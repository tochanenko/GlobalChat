package com.tochanenko.beglobalchat.utils;

import java.util.regex.Pattern;

public final class ValidationConstants {
    ValidationConstants() {}

    public static final int MAX_USERNAME_LENGTH = 48;
    public static final int MIN_USERNAME_LENGTH = 3;
    public static final int MAX_PASSWORD_LENGTH = 72;
    public static final int MIN_PASSWORD_LENGTH = 12;
    public static final int PASSWORD_STRENGTH = 12;

    public static final int JWT_TOKEN_SECONDS_ALIVE_TIME = 900;

    public static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );
}

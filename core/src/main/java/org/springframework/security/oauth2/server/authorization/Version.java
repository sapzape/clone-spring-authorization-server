package org.springframework.security.oauth2.server.authorization;

public final class Version {

	private static final int MAJOR = 0;

	private static final int MINOR = 0;

	private static final int PATCH = 1;

	public static final long SERIAL_VERSION_UID = getVersion().hashCode();

	private static String getVersion() {
		return MAJOR + "." + MINOR + "." + PATCH;
	}
}

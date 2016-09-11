/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.config.client;

import static java.util.Objects.requireNonNull;

import java.net.MalformedURLException;
import java.net.URL;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Dave Syer
 * @author Felix Kissel
 *
 */
@ConfigurationProperties(ConfigClientProperties.PREFIX)
public class ConfigClientProperties {
	
	private static final String DEFAULT_USERNAME_user = "user";

	private static class UsernamePasswordPair {

		private final String username;
		
		private final String password;

		public UsernamePasswordPair(String username, String password) {
			this.username = StringUtils.hasText(username) ? username.trim() : null;
			this.password = StringUtils.hasText(password) ? password.trim() : null;
		}

		public String getUsername() {
			return username;
		}
		
		public String getPassword() {
			return password;
		}
		
		@Override
		public String toString() {
			return getClass().getSimpleName() + " [username=" + username + ", password=*******]";
		}
		
		public UsernamePasswordPair copyAndComplementWith(UsernamePasswordPair usernamePasswordPair) {
			String username = this.username != null ? this.username : usernamePasswordPair.getUsername();
			String password = this.password != null ? this.password : usernamePasswordPair.getPassword();
			return new UsernamePasswordPair(username, password);
		}

		public Credentials toCredentialsOrNull() {
			if(this.password == null) {
				return null;
			}
			return new Credentials(this.username == null ? DEFAULT_USERNAME_user : this.username, this.password);
		}

	}
	
	private static class Credentials extends UsernamePasswordPair{

		public Credentials(String username, String password) {
			super(requireNonNull(username), requireNonNull(password));
		}

		@Override
		public String toString() {
			return "Credentials [getUsername()=" + getUsername() + ", getPassword()=******]";
		}
		
	}
	
	private static class ConfigServerEndpoint {

		private final String rawUri;
		
		private final Credentials credentials;


		public ConfigServerEndpoint(String rawUri, Credentials credentials) {
			this.rawUri = rawUri;
			this.credentials = credentials;
		}

		public String getRawUri() {
			return rawUri;
		}

		public Credentials getCredentials() {
			return credentials;
		}
		
		@Override
		public String toString() {
			return "ConfigServerEndpoint [rawUri=" + rawUri + ", credentials="
					+ credentials + "]";
		}

	}

	public static final String PREFIX = "spring.cloud.config";
	public static final String TOKEN_HEADER = "X-Config-Token";
	public static final String STATE_HEADER = "X-Config-State";

	/**
	 * Flag to say that remote configuration is enabled. Default true;
	 */
	private boolean enabled = true;

	/**
	 * The default profile to use when fetching remote configuration (comma-separated).
	 * Default is "default".
	 */
	private String profile = "default";

	/**
	 * Name of application used to fetch remote properties.
	 */
	@Value("${spring.application.name:application}")
	private String name;

	/**
	 * The label name to use to pull remote configuration properties. The default is set
	 * on the server (generally "master" for a git based server).
	 */
	private String label;

	/**
	 * The username to use (HTTP Basic) when contacting the remote server.
	 */
	private String username;

	/**
	 * The password to use (HTTP Basic) when contacting the remote server.
	 */
	private String password;

	/**
	 * The URI of the remote server (default http://localhost:8888).
	 */
	private String uri = "http://localhost:8888";

	/**
	 * Discovery properties.
	 */
	private Discovery discovery = new Discovery();

	/**
	 * Flag to indicate that failure to connect to the server is fatal (default false).
	 */
	private boolean failFast = false;

	/**
	 * Security Token passed thru to underlying environment repository.
	 */
	private String token;

	/**
	 * Authorization token used by the client to connect to the server.
	 */
	private String authorization;

	private ConfigClientProperties() {
	}

	public ConfigClientProperties(Environment environment) {
		String[] profiles = environment.getActiveProfiles();
		if (profiles.length == 0) {
			profiles = environment.getDefaultProfiles();
		}
		this.setProfile(StringUtils.arrayToCommaDelimitedString(profiles));
	}

	public boolean isEnabled() {
		return this.enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getRawUri() {
		return extractCredentials().getRawUri();
	}

	public String getUri() {
		return this.uri;
	}

	public void setUri(String url) {
		this.uri = url;
	}

	public String getName() {
		return this.name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getProfile() {
		return this.profile;
	}

	public void setProfile(String env) {
		this.profile = env;
	}

	public String getLabel() {
		return this.label;
	}

	public void setLabel(String label) {
		this.label = label;
	}

	public String getUsername() {
		Credentials credentials = extractCredentials().getCredentials();
		return credentials == null ? null : credentials.getUsername(); 
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		Credentials credentials = extractCredentials().getCredentials();
		return credentials == null ? null : credentials.getPassword(); 
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Discovery getDiscovery() {
		return this.discovery;
	}

	public void setDiscovery(Discovery discovery) {
		this.discovery = discovery;
	}

	public boolean isFailFast() {
		return this.failFast;
	}

	public void setFailFast(boolean failFast) {
		this.failFast = failFast;
	}

	public String getToken() {
		return this.token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getAuthorization() {
		return this.authorization;
	}

	public void setAuthorization(String authorization) {
		this.authorization = authorization;
	}

	
	protected ConfigServerEndpoint extractCredentials() {
		UsernamePasswordPair explicitCredentials = getExplicitCredentials();
		try {
			URL url = new URL(this.uri);
			String userInfo = url.getUserInfo();
			String uriWithoutCredentials = UriComponentsBuilder.fromHttpUrl(this.uri).userInfo(null)
					.build().toUriString();
			UsernamePasswordPair uriCredentials = parseUserInfoString(userInfo);
			UsernamePasswordPair mergedCredentials = explicitCredentials.copyAndComplementWith(uriCredentials);

			Credentials resultCredentials = mergedCredentials.toCredentialsOrNull();
			return new ConfigServerEndpoint(uriWithoutCredentials, resultCredentials);
		}
		catch (MalformedURLException e) {
			throw new IllegalStateException("Invalid URL: " + uri);
		}
	}
	
	private static UsernamePasswordPair parseUserInfoString(String userInfo) {
		if(userInfo == null || userInfo.trim().equals(":")) {
			return new UsernamePasswordPair(null, null);
		}
		if (userInfo.contains(":")) {
			String[] split = userInfo.split(":", -1);
			return new UsernamePasswordPair(split[0], split[1]);
		}
		else {
			return new UsernamePasswordPair(userInfo, null);
		}
	}

	private UsernamePasswordPair getExplicitCredentials() {
		if (StringUtils.hasText(this.password)) {
			return new UsernamePasswordPair(this.username, this.password);
		}
		else {
			return new UsernamePasswordPair(null, null);
		}
	}

	public static class Discovery {
		public static final String DEFAULT_CONFIG_SERVER = "configserver";

		/**
		 * Flag to indicate that config server discovery is enabled (config server URL will be
		 * looked up via discovery).
		 */
		private boolean enabled;
		/**
		 * Service id to locate config server.
		 */
		private String serviceId = DEFAULT_CONFIG_SERVER;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public String getServiceId() {
			return this.serviceId;
		}

		public void setServiceId(String serviceId) {
			this.serviceId = serviceId;
		}

	}

	public ConfigClientProperties override(
			org.springframework.core.env.Environment environment) {
		ConfigClientProperties override = new ConfigClientProperties();
		BeanUtils.copyProperties(this, override);
		override.setName(
				environment.resolvePlaceholders("${" + ConfigClientProperties.PREFIX
						+ ".name:${spring.application.name:application}}"));
		if (environment.containsProperty(ConfigClientProperties.PREFIX + ".profile")) {
			override.setProfile(
					environment.getProperty(ConfigClientProperties.PREFIX + ".profile"));
		}
		if (environment.containsProperty(ConfigClientProperties.PREFIX + ".label")) {
			override.setLabel(
					environment.getProperty(ConfigClientProperties.PREFIX + ".label"));
		}
		return override;
	}

	@Override
	public String toString() {
		return "ConfigClientProperties [enabled=" + this.enabled + ", profile="
				+ this.profile + ", name=" + this.name + ", label="
				+ (this.label == null ? "" : this.label) + ", username=" + this.username
				+ ", password=" + this.password + ", uri=" + this.uri
				+ ", authorization=" + this.authorization
				+ ", discovery.enabled=" + this.discovery.enabled + ", failFast="
				+ this.failFast + ", token=" + this.token + "]";
	}

}

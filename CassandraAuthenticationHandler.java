package org.apereo.cas.custom.adaptors.cassandra;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.CredentialExpiredException;
import javax.security.auth.login.FailedLoginException;

import org.apereo.cas.authentication.AccountDisabledException;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.BasicCredentialMetaData;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.DefaultHandlerResult;
import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.InvalidLoginLocationException;
import org.apereo.cas.authentication.InvalidLoginTimeException;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;

/**
 * Custom AuthenticationHandler that talks to Cassandra db
 */
@Component("cassandraAuthenticationHandler")
public class CassandraAuthenticationHandler implements AuthenticationHandler {
    
    /** Default mapping of special usernames to exceptions raised when that user attempts authentication. */
    private static final Map<String, Exception> DEFAULT_USERNAME_ERROR_MAP = new HashMap<>();

    @Autowired
    private CassandraClient cassandraClient;
    
    protected PrincipalFactory principalFactory = new DefaultPrincipalFactory();

    /** Instance of logging for subclasses. */
    private transient Logger logger = LoggerFactory.getLogger(this.getClass());

    /** Map of special usernames to exceptions that are raised when a user with that name attempts authentication. */
    private Map<String, Exception> usernameErrorMap = DEFAULT_USERNAME_ERROR_MAP;


    static {
        DEFAULT_USERNAME_ERROR_MAP.put("accountDisabled", new AccountDisabledException("Account disabled"));
        DEFAULT_USERNAME_ERROR_MAP.put("accountLocked", new AccountLockedException("Account locked"));
        DEFAULT_USERNAME_ERROR_MAP.put("badHours", new InvalidLoginTimeException("Invalid logon hours"));
        DEFAULT_USERNAME_ERROR_MAP.put("badWorkstation", new InvalidLoginLocationException("Invalid workstation"));
        DEFAULT_USERNAME_ERROR_MAP.put("passwordExpired", new CredentialExpiredException("Password expired"));
    }

    public CassandraAuthenticationHandler() {
    	logger.debug("1816");
    }

    @PostConstruct
    private void init() {
    }

    public void setUsernameErrorMap(final Map<String, Exception> map) {
        this.usernameErrorMap = map;
    }

    @Override
    public HandlerResult authenticate(final Credential credential)
            throws GeneralSecurityException, PreventedException {

        final UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential) credential;
        final String username = usernamePasswordCredential.getUsername();
        final String password = usernamePasswordCredential.getPassword();

        final Exception exception = this.usernameErrorMap.get(username);
        if (exception instanceof GeneralSecurityException) {
            throw (GeneralSecurityException) exception;
        } else if (exception instanceof PreventedException) {
            throw (PreventedException) exception;
        } else if (exception instanceof RuntimeException) {
            throw (RuntimeException) exception;
        } else if (exception != null) {
            logger.debug("Cannot throw checked exception {} since it is not declared by method signature.",
                    exception.getClass().getName(),
                    exception);
        }

        if(verifyCreds(username, password)) {
            logger.debug("User [{}] was successfully authenticated.", username);
            return new DefaultHandlerResult(this, new BasicCredentialMetaData(credential),
                    this.principalFactory.createPrincipal(username));        	
        }
        
        logger.debug("User [{}] failed authentication", username);
        throw new FailedLoginException();
    }

	private boolean verifyCreds(String username, String password) {
		String cql = Constants.USER_QUERY.replace(Constants.LABEL_USERNAME, username);
		logger.info("cql: {}", cql);
		Row row = cassandraClient.getQueryResult(cql).one();
		if(row == null) {
			return false;
		}
		String encodedPassword = row.getString("password");
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder.matches(password, encodedPassword);
	}

	@Override
    public boolean supports(final Credential credential) {
        return credential instanceof UsernamePasswordCredential;
    }

    @Override
    public String getName() {
        return getClass().getSimpleName();
    }
}

# cas5-cassandra-athentication
Custom Authentication handler where user creds are stored in Cassandra db.

# Followed below steps:
1. Created package org.apereo.cas.<custom>.adaptors.cassandra
2. CassandraAuthenticationHandler

    public class CassandraAuthenticationHandler implements AuthenticationHandler {

    }

3. Created org.apereo.cas.<custom>.adaptors.cassandra.config.CasCassandraConfiguration similar to org.apereo.cas.adaptors.generic.config.CasGenericConfiguration.

    @Configuration("casCassandraConfiguration")
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    public class CasCassandraConfiguration {

        @RefreshScope
        @Bean
        public AuthenticationHandler cassandraAuthenticationHandler() {
            final CassandraAuthenticationHandler h = new CassandraAuthenticationHandler();
            return h;
        }


        @PostConstruct
        public void initializeAuthenticationHandler() {
            System.out.println("1755");
            this.authenticationHandlersResolvers.put(cassandraAuthenticationHandler(), personDirectoryPrincipalResolver);
        }

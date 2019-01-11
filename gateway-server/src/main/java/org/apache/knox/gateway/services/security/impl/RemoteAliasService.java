/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.services.security.impl;

import org.apache.knox.gateway.GatewayMessages;
import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.security.RemoteAliasServiceProvider;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.MasterService;
import org.apache.knox.gateway.util.PasswordUtils;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * An {@link AliasService} implementation based on remote service registry.
 * <p>
 * This class encapsulates the default AliasService implementation which uses
 * local keystore to store the aliases. The order in which Aliases are stored are
 * <ul>
 * <li>Local Keystore</li>
 * <li>Remote Registry</li>
 * </ul>
 *
 * @since 1.1.0
 */
public class RemoteAliasService implements AliasService {
  public static final String REMOTE_ALIAS_SERVICE_TYPE = "type";

  private static final GatewayMessages LOG = MessagesFactory.get(GatewayMessages.class);

  private final AliasService localAliasService;
  private final MasterService ms;

  private AliasService remoteAliasServiceImpl;

  public RemoteAliasService(AliasService localAliasService, MasterService ms) {
    this.localAliasService = localAliasService;
    this.ms = ms;
  }

  /**
   * Get a list of all aliases for a given cluster.
   * Remote aliases are preferred over local.
   *
   * @param clusterName cluster name
   * @return List of all the aliases
   */
  @Override
  public List<String> getAliasesForCluster(final String clusterName) throws AliasServiceException {
    List<String> remoteAliases = new ArrayList<>();

    /* If we have remote registry configured, query it */
    if (remoteAliasServiceImpl != null) {
      remoteAliases = remoteAliasServiceImpl.getAliasesForCluster(clusterName);
    }

    List<String> localAliases = localAliasService
        .getAliasesForCluster(clusterName);

    if(localAliases != null) {
      for (final String alias : localAliases) {
        if (!remoteAliases.contains(alias.toLowerCase(Locale.ROOT))) {
          remoteAliases.add(alias);
        }
      }
    }

    return remoteAliases;
  }

  @Override
  public void addAliasForCluster(final String clusterName,
      final String givenAlias, final String value)
      throws AliasServiceException {

    /* convert all alias names to lower case since JDK expects the same behaviour */
    final String alias = givenAlias.toLowerCase(Locale.ROOT);

    /* first add the alias to the local keystore */
    localAliasService.addAliasForCluster(clusterName, alias, value);

    if (remoteAliasServiceImpl != null) {
      remoteAliasServiceImpl.addAliasForCluster(clusterName, alias, value);
    }
  }

  @Override
  public void removeAliasForCluster(final String clusterName, final String givenAlias)
      throws AliasServiceException {
    /* convert all alias names to lower case since JDK expects the same behaviour */
    final String alias = givenAlias.toLowerCase(Locale.ROOT);

    /* first remove it from the local keystore */
    localAliasService.removeAliasForCluster(clusterName, alias);

    /* If we have remote registry configured, query it */
    if (remoteAliasServiceImpl != null) {
      remoteAliasServiceImpl.removeAliasForCluster(clusterName, alias);
    }
  }

  @Override
  public char[] getPasswordFromAliasForCluster(String clusterName, String alias)
      throws AliasServiceException {
    return getPasswordFromAliasForCluster(clusterName, alias, false);
  }

  @Override
  public char[] getPasswordFromAliasForCluster(String clusterName,
      String givenAlias, boolean generate) throws AliasServiceException {
    /* convert all alias names to lower case since JDK expects the same behaviour */
    final String alias = givenAlias.toLowerCase(Locale.ROOT);

    /* Generate a new password  */
    if (generate) {
      generateAliasForCluster(clusterName, alias);
    }

    char[] password = null;

    /* try to get it from remote registry */
    if (remoteAliasServiceImpl != null) {
      password = remoteAliasServiceImpl.getPasswordFromAliasForCluster(clusterName, alias);
    }

    /*
     * If
     * 1. Remote registry not configured or
     * 2. Password not found for given alias in remote registry,
     * Then try local keystore
     */
    if(password == null) {
      /* try to get it from the local keystore, ignore generate flag. */
      password = localAliasService.getPasswordFromAliasForCluster(clusterName, alias);
    }

    /* found nothing */
    return password;
  }

  @Override
  public void generateAliasForCluster(final String clusterName, final String alias)
      throws AliasServiceException {
    /* auto-generated password */
    final String passwordString = PasswordUtils.generatePassword(16);
    addAliasForCluster(clusterName, alias, passwordString);
  }

  @Override
  public char[] getPasswordFromAliasForGateway(String alias)
      throws AliasServiceException {
    return getPasswordFromAliasForCluster(NO_CLUSTER_NAME, alias);
  }

  @Override
  public char[] getGatewayIdentityPassphrase() throws AliasServiceException {
    char[] password = null;
    if(remoteAliasServiceImpl != null) {
      password = remoteAliasServiceImpl.getGatewayIdentityPassphrase();
    }

    if(password == null) {
      password = localAliasService.getGatewayIdentityPassphrase();
    }

    return password;
  }

  @Override
  public char[] getGatewayIdentityKeystorePassword() throws AliasServiceException {
    char[] password = null;
    if(remoteAliasServiceImpl != null) {
      password = remoteAliasServiceImpl.getGatewayIdentityKeystorePassword();
    }

    if(password == null) {
      password = localAliasService.getGatewayIdentityKeystorePassword();
    }

    return password;
  }

  @Override
  public char[] getSigningKeyPassphrase() throws AliasServiceException {
    char[] password = null;
    if(remoteAliasServiceImpl != null) {
      password = remoteAliasServiceImpl.getSigningKeyPassphrase();
    }

    if(password == null) {
      password = localAliasService.getSigningKeyPassphrase();
    }

    return password;
  }

  @Override
  public char[] getSigningKeystorePassword() throws AliasServiceException {
    char[] password = null;
    if(remoteAliasServiceImpl != null) {
      password = remoteAliasServiceImpl.getSigningKeystorePassword();
    }

    if(password == null) {
      password = localAliasService.getSigningKeystorePassword();
    }

    return password;
  }

  @Override
  public void generateAliasForGateway(final String alias)
      throws AliasServiceException {
    generateAliasForCluster(NO_CLUSTER_NAME, alias);
  }

  @Override
  public Certificate getCertificateForGateway(final String alias)
      throws AliasServiceException {
    /* We don't store certs in remote registry so we just delegate certs to keystore (DefaultAliasService.getCertificateForGateway) */
    return localAliasService.getCertificateForGateway(alias);
  }

  @Override
  public void init(final GatewayConfig config, final Map<String, String> options)
      throws ServiceLifecycleException {
    Map<String, String> remoteAliasServiceConfigs = config.getRemoteAliasServiceConfiguration();

    if(config.isRemoteAliasServiceEnabled() && remoteAliasServiceConfigs != null) {
      String remoteAliasServiceType = remoteAliasServiceConfigs.get(REMOTE_ALIAS_SERVICE_TYPE);
      ServiceLoader<RemoteAliasServiceProvider> providers =
          ServiceLoader.load(RemoteAliasServiceProvider.class);
      for (RemoteAliasServiceProvider provider : providers) {
        if(provider.getType().equalsIgnoreCase(remoteAliasServiceType)) {
          LOG.remoteAliasServiceEnabled();
          remoteAliasServiceImpl = provider.newInstance(localAliasService, ms);
          remoteAliasServiceImpl.init(config, options);
          break;
        }
      }
    } else {
      LOG.remoteAliasServiceDisabled();
    }
  }

  @Override
  public void start() throws ServiceLifecycleException {
    if (remoteAliasServiceImpl != null) {
      remoteAliasServiceImpl.start();
    }
  }

  @Override
  public void stop() throws ServiceLifecycleException {
    if(remoteAliasServiceImpl != null) {
      remoteAliasServiceImpl.stop();
    }
  }
}

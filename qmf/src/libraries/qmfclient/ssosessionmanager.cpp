/****************************************************************************
**
** Copyright (C) 2013 Jolla Ltd.
** Contact: Valério Valério <valerio.valerio@jollamobile.com>
**
** This file is part of the Qt Messaging Framework.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and Digia.  For licensing terms and
** conditions see http://qt.digia.com/licensing.  For further information
** use the contact form at http://qt.digia.com/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU Lesser General Public License version 2.1 requirements
** will be met: http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** In addition, as a special exception, Digia gives you certain additional
** rights.  These rights are described in the Digia Qt LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3.0 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU General Public License version 3.0 requirements will be
** met: http://www.gnu.org/copyleft/gpl.html.
**
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "ssosessionmanager.h"
#include "ssoaccountmanager.h"
#include <qmaillog.h>

#include <Accounts/AccountService>
#include <Accounts/AuthData>

/*!
    \class SSOSessionManager

    \preliminary
    \brief The SSOSessionManager class provides a manager to query authentication details
    from accounts-sso framework.
    \ingroup messaginglibrary
*/

/*!
    \fn ssoSessionError(const QString &error)

    This signal is emitted when we receive a reply to an authentication
    request from accounts-sso framework and a error occurred, the error
    details are described by \a error.

    \sa ssoSessionResponse()
*/

/*!
    \fn ssoSessionResponse(const QList<QByteArray> &ssoLogin)

    This signal is emitted when we receive a reply to a authentication
    request from accounts-sso framework, the authentication details are
    described by \a ssologin.

    \sa ssoSessionError()
*/

SSOSessionManager::SSOSessionManager(QObject *parent)
    : QObject(parent),
      _waitForSso(false),
      _identity(0),
      _session(0)
{
    _availableAuthMethods = SSOAuthFactory::keys();
}

SSOSessionManager::~SSOSessionManager()
{
}

bool SSOSessionManager::authPluginAvailable(const QString &method) const
{
    return _availableAuthMethods.contains(method);
}

/*!
    Cancels the current session.
*/

void SSOSessionManager::cancel()
{
    if (_waitForSso) {
        _session->cancel();
        // Canceled by other process,
        // no need to emit any error from here.
        _waitForSso = false;
    }
}

/*!
    Creates a new SSO identity for the account identified by \a id for
    the service to \a serviceType with the authentication type \a serviceAuthentication.

    Returns true if the account has one email service enabled and a valid identity stored
    in ths accounts-sso database, otherwise returns false.

    The authentication details will be queried from accounts-sso framework and reported by
    ssoSessionResponse() signal, if a error occurs it will be reported by ssoSessionError()
    signal.

    \sa ssoSessionResponse(), ssoSessionError()
*/

bool SSOSessionManager::createSsoIdentity(const QMailAccountId &id, const QString &serviceType,
                                          int serviceAuthentication)
{
    deleteSsoIdentity();
    _serviceAuthentication = serviceAuthentication;
    _serviceType = serviceType;

    SSOAccountManager manager;
    Accounts::Account* account = manager->account(static_cast<Accounts::AccountId>(id.toULongLong()));
    if (!account)
        return false;

    Accounts::ServiceList emailServices = account->enabledServices();
    if (1 != emailServices.count()) {
        qMailLog(Messaging) << Q_FUNC_INFO << "Account must have one active e-mail service, but it has "
                       << emailServices.count();
        return false;
    }

    account->selectService(emailServices.first());
    Accounts::AccountService* emailService = new Accounts::AccountService(account, account->selectedService());
    Accounts::AuthData auth = emailService->authData();
    _accountProvider = account->providerName();
    _authMethod = auth.method();
    _authMechanism = auth.mechanism();
    _authParameters = auth.parameters();

    if (!authPluginAvailable(_authMethod)) {
        qMailLog(Messaging) << Q_FUNC_INFO
                            << "SSO error: No authentication plugin found for the following method: " + _authMethod;
        return false;
    }

    quint32 credentialsId = account->valueAsInt(serviceCredentialsId(_serviceType), 0);
    _authUsername = account->valueAsString("emailaddress");

    if (_authUsername.isEmpty()) {
        qMailLog(Messaging) << Q_FUNC_INFO
                            << "SSO error: User name is emtpy.";
        return false;
    }

    // Some plugins stores an identity per service.
    // If there is no specific credentials for the specific service than we should check regular credentialsId.
    // This allows to store different credentials for incoming and outgoing servers for example.
    if (credentialsId == 0) {
        credentialsId = account->credentialsId();
    }

    _identity = SignOn::Identity::existingIdentity(credentialsId, this);

    if (_identity) {

        qMailLog(Messaging) << Q_FUNC_INFO << "Creating SSO identity for the service " << _serviceType
                            << " from account " << id.toULongLong()
                            << " using authentication method " << _authMethod;
       _session = _identity->createSession(_authMethod);
        Q_ASSERT (_session);
        ENFORCE(connect(_session, SIGNAL(response(SignOn::SessionData)),
                        this, SLOT(ssoResponse(SignOn::SessionData))));
        ENFORCE(connect(_session, SIGNAL(error(SignOn::Error)),
                        this, SLOT(ssoSessionError(SignOn::Error))));
        _waitForSso = true;
        _authService = SSOAuthFactory::createService(_authMethod);
        _session->process(_authService->sessionData(_accountProvider, _authParameters, false), _authMechanism);
        return true;
    } else {
        _session = 0;
        return false;
    }
}

/*!
    Deletes the SSO identity.
*/
void SSOSessionManager::deleteSsoIdentity()
{
    _ssoLogin = QByteArray();
    _authMethod.clear();
    _serviceType.clear();
    if (_identity) {
        Q_ASSERT (_session);
        _identity->destroySession(_session);
        delete _identity;
        _identity = 0;
    }
}

/*!
    Recreates the SSO identity.

    This function should be used when stored authentication details
    are no longer valid. By default \a setUiPolicy is set to true,
    in this case if the authentication plugin in use has a UI policy
    defined this function can trigger additional processes that will request
    actions from the user.
*/
void SSOSessionManager::recreateSsoIdentity(bool setUiPolicy)
{
    qMailLog(Messaging) << Q_FUNC_INFO << "Recreating SSO identity using auth method "
                           << _authMethod;
    if (_identity && _session && !_waitForSso) {
        if (!_authService)
            _authService = SSOAuthFactory::createService(_authMethod);

        _waitForSso = true;
        _session->process(_authService->sessionData(_accountProvider, _authParameters, setUiPolicy), _authMechanism);
    } else {
        _waitForSso = true;
        emit ssoSessionError("SSO error: Identity is not valid, can't recreate session.");
    }
}

QString SSOSessionManager::serviceCredentialsId(const QString &serviceType) const
{
    if (serviceType == "imap4") {
        return "imap4/CredentialsId";
    } else if (serviceType == "pop3") {
        return "pop3/CredentialsId";
    } else if (serviceType == "smtp") {
        return "smtp/CredentialsId";
    } else {
        return QString();
    }
}

void SSOSessionManager::ssoResponse(const SignOn::SessionData &sessionData)
{
    if (_waitForSso) {
        _waitForSso = false;
        if (!_authService)
            _authService = SSOAuthFactory::createService(_authMethod);

        QList<QByteArray> ssoLogin = _authService->authentication(sessionData, _serviceType,
                                                                  _authUsername, _serviceAuthentication);
        emit ssoSessionResponse(ssoLogin);
    }
}

void SSOSessionManager::ssoSessionError(const SignOn::Error &code)
{
    if (_waitForSso) {
        _waitForSso = false;
        _ssoLogin = QByteArray();
        emit ssoSessionError(QString("SSO error %1: %2").arg(code.type()).arg(code.message()));
    }
}

/*!
    Returns true if we are waiting for a reply
    from accounts-sso framework, otherwise false.
*/
bool SSOSessionManager::waitForSso()
{
    return _waitForSso;
}


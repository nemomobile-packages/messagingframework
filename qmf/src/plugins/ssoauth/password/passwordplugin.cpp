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

#include "passwordplugin.h"
#include "qmailnamespace.h"

// From Qt Messaging Framework IMAP plugin
// Ensure a string is quoted, if required for IMAP transmission
// As per IMAP4 rfc 2060 section 4.2
QString quoteIMAPString(const QString& input)
{
    // We can't easily catch controls other than those caught by \\s...
    QRegExp atomSpecials("[\\(\\)\\{\\s\\*%\\\\\"\\]]");

    // The empty string must be quoted
    if (input.isEmpty())
        return QString("\"\"");

    if (atomSpecials.indexIn(input) == -1)
        return input;

    // We need to quote this string because it is not an atom
    QString result(input);

    QString::iterator begin = result.begin(), it = begin;
    while (it != result.end()) {
        // We need to escape any characters specially treated in quotes
        if ((*it) == '\\' || (*it) == '"') {
            int pos = (it - begin);
            result.insert(pos, '\\');
            it = result.begin() + (pos + 1);
        }
        ++it;
    }

    return QMail::quoteString(result);
}

QByteArray quoteIMAPString(const QByteArray& input)
{
    return quoteIMAPString(QString::fromLatin1(input)).toLatin1();
}

SSOPasswordPlugin::SSOPasswordPlugin(QObject *parent)
    : SSOAuthService(parent)
{
}

SSOPasswordPlugin::~SSOPasswordPlugin()
{
}

QList<QByteArray> SSOPasswordPlugin::getIMAPAuthentication(const QString &password,
                                                    const QString &username, int serviceAuthentication) const
{
    if (serviceAuthentication == QMail::PlainMechanism) {
        QByteArray user(username.toLatin1());
        QByteArray pass(password.toLatin1());
        return QList<QByteArray>() << QByteArray("AUTHENTICATE PLAIN ") + QByteArray(user + '\0' + user + '\0' + pass).toBase64();
    } if (serviceAuthentication == QMail::CramMd5Mechanism) {
        return QList<QByteArray>() << QByteArray(password.toLatin1());
    } else {
        return QList<QByteArray>() << QByteArray("LOGIN") + ' ' + quoteIMAPString(username.toLatin1())
                                   + ' ' + quoteIMAPString(password.toLatin1());
    }
}

QList<QByteArray> SSOPasswordPlugin::getPOPAuthentication(const QString &password,
                                                   const QString &username, int serviceAuthentication) const
{
    QList<QByteArray> result;
    if (serviceAuthentication == QMail::CramMd5Mechanism) {
        result.append(QByteArray(password.toLatin1()));
    } else {
        result.append(QByteArray("USER ") + username.toLatin1());
        result.append(QByteArray("PASS ") + password.toLatin1());
    }

    return result;
}

QList<QByteArray> SSOPasswordPlugin::getSMTPAuthentication(const QString &password,
                                                    const QString &username, int serviceAuthentication) const
{
    QList<QByteArray> result;
    QByteArray user(username.toUtf8());
    QByteArray pass(password.toUtf8());

    if (serviceAuthentication == QMail::LoginMechanism) {
        result.append(QByteArray("AUTH LOGIN"));
        result.append(QByteArray(user));
        result.append(QByteArray(pass));
    } else if (serviceAuthentication == QMail::PlainMechanism) {
        result.append(QByteArray("AUTH PLAIN ") + QByteArray(user + '\0' + user + '\0' + pass).toBase64());
        result.append(QByteArray(user + '\0' + user + '\0' + pass));
    } else if (serviceAuthentication == QMail::CramMd5Mechanism) {
        result.append(QByteArray(pass));
    }
    return result;
}

SSOAuthService* SSOPasswordPlugin::createService()
{
    return this;
}

QString SSOPasswordPlugin::key() const
{
    return "password";
}
QList<QByteArray> SSOPasswordPlugin::authentication(const SignOn::SessionData &sessionData,
                                                const QString &serviceType, const QString &userName, int serviceAuthentication) const
{
    QString password = sessionData.Secret();
    QString username = sessionData.UserName();

    if (username.isEmpty())
        username = userName;

    if (serviceType == "imap4") {
        return getIMAPAuthentication(password, username, serviceAuthentication);
    } else if (serviceType == "pop3") {
        return getPOPAuthentication(password, username, serviceAuthentication);
    } else if (serviceType == "smtp") {
        return getSMTPAuthentication(password, username, serviceAuthentication);
    } else {
        return QList<QByteArray>();
    }
}

void SSOPasswordPlugin::credentialsNeedUpdate(int accountId)
{
    // For the password method we don't do anything, messageserver
    // already informs the clients about login failed.
    Q_UNUSED(accountId);
}

SignOn::SessionData SSOPasswordPlugin::sessionData(const QString &accountProvider,  QVariantMap authParameters) const
{
    Q_UNUSED(accountProvider);
    Q_UNUSED(authParameters);

    SignOn::SessionData data;
    data.setUiPolicy(SignOn::NoUserInteractionPolicy);
    return data;
}

#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
Q_EXPORT_PLUGIN2(password,SSOPasswordPlugin)
#endif

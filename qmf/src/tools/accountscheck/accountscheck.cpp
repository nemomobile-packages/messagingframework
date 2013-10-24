
#include <QDebug>
#include <QCoreApplication>
#include <Accounts/Manager>

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);

    qDebug() << "QMF accounts check: checking email accounts in the system";

    Accounts::Manager manager;
    Accounts::AccountIdList accountIDList = manager.accountListEnabled("e-mail");

    // check if there are any accounts
    if(accountIDList.size() > 0) {
        qDebug() << "QMF accounts check: found enabled accounts";
        return 0;
    }

    qDebug() << "QMF accounts check: no accounts found";
    return 1;
}

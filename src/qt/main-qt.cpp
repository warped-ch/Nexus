/*******************************************************************************************
 
			Hash(BEGIN(Satoshi[2010]), END(W.J.[2012])) == Videlicet[2014] ++
   
 [Learn and Create] Viz. http://www.opensource.org/licenses/mit-license.php
  
*******************************************************************************************/
 
#include "core/gui.h"
#include "models/clientmodel.h"
#include "models/walletmodel.h"
#include "models/optionsmodel.h"
#include "util/guiutil.h"

#include "../main.h"
#include "../util/ui_interface.h"
#include "core/qtipcserver.h"

#if QT_VERSION < QT_VERSION_CHECK(5,0,0)
 #include <QApplication>
 #include <QMessageBox>
 #include <QSplashScreen>
#else
 #include <QtWidgets/QApplication>
 #include <QtWidgets/QMessageBox>
 #include <QtWidgets/QSplashScreen>
#endif
#include <QTextCodec>
#include <QLocale>
#include <QTranslator>
#include <QLibraryInfo>
#include <QMessageBox>
#include <QFile>
#include <QDir>

#include <boost/interprocess/ipc/message_queue.hpp>

#if defined(NEXUS_NEED_QT_PLUGINS) && !defined(_NEXUS_QT_PLUGINS_INCLUDED)
#define _NEXUS_QT_PLUGINS_INCLUDED
#define __INSURE__
#include <QtPlugin>
Q_IMPORT_PLUGIN(qcncodecs)
Q_IMPORT_PLUGIN(qjpcodecs)
Q_IMPORT_PLUGIN(qtwcodecs)
Q_IMPORT_PLUGIN(qkrcodecs)
Q_IMPORT_PLUGIN(qtaccessiblewidgets)
#endif

// Need a global reference for the notifications to find the GUI
static NexusGUI *guiref;
static QSplashScreen *splashref;
static WalletModel *walletmodel;
static ClientModel *clientmodel;

int ThreadSafeMessageBox(const std::string& message, const std::string& caption, int style)
{
    // Message from network thread
    if(guiref)
    {
        bool modal = (style & wxMODAL);
        // in case of modal message, use blocking connection to wait for user to click OK
        QMetaObject::invokeMethod(guiref, "error",
                                   modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
                                   Q_ARG(QString, QString::fromStdString(caption)),
                                   Q_ARG(QString, QString::fromStdString(message)),
                                   Q_ARG(bool, modal));
    }
    else
    {
        printf("%s: %s\n", caption.c_str(), message.c_str());
        fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    }
    return 4;
}

bool ThreadSafeAskFee(int64 nFeeRequired, const std::string& strCaption)
{
    if(!guiref)
        return false;
    if(nFeeRequired < Core::MIN_TX_FEE || nFeeRequired <= Core::nTransactionFee || fDaemon)
        return true;
    bool payFee = false;

    QMetaObject::invokeMethod(guiref, "askFee", GUIUtil::blockingGUIThreadConnection(),
                               Q_ARG(qint64, nFeeRequired),
                               Q_ARG(bool*, &payFee));

    return payFee;
}

void ThreadSafeHandleURI(const std::string& strURI)
{
    if(!guiref)
        return;

    QMetaObject::invokeMethod(guiref, "handleURI", GUIUtil::blockingGUIThreadConnection(),
                               Q_ARG(QString, QString::fromStdString(strURI)));
}

void MainFrameRepaint()
{
    if(clientmodel)
        QMetaObject::invokeMethod(clientmodel, "update", Qt::QueuedConnection);
    if(walletmodel)
        QMetaObject::invokeMethod(walletmodel, "update", Qt::QueuedConnection);
}

void AddressBookRepaint()
{
    if(walletmodel)
        QMetaObject::invokeMethod(walletmodel, "updateAddressList", Qt::QueuedConnection);
}

void InitMessage(const std::string &message)
{
    if(splashref)
    {
        splashref->showMessage(QString::fromStdString(message), Qt::AlignBottom|Qt::AlignHCenter, QColor(0, 0, 0));
        QApplication::instance()->processEvents();
    }
}

void QueueShutdown()
{
    QMetaObject::invokeMethod(QCoreApplication::instance(), "quit", Qt::QueuedConnection);
}

/*
   Translate string to current locale using Qt.
 */
std::string _(const char* psz)
{
    return QCoreApplication::translate("Nexus-core", psz).toStdString();
}

/* Handle runaway exceptions. Shows a message box with the problem and quits the program.
 */
static void handleRunawayException(std::exception *e)
{
    PrintExceptionContinue(e, "Runaway exception");
    QMessageBox::critical(0, "Runaway exception", NexusGUI::tr("A fatal error occured. Nexus can no longer continue safely and will quit.") + QString("\n\n") + QString::fromStdString(strMiscWarning));
    exit(1);
}

#ifdef WIN32
#define strncasecmp strnicmp
#endif
#ifndef NEXUS_QT_TEST
int main(int argc, char *argv[])
{

#if !defined(MAC_OSX) && !defined(WIN32)
// TODO: implement qtipcserver.cpp for Mac and Windows

    // Do this early as we don't want to bother initializing if we are just calling IPC
    for (int i = 1; i < argc; i++)
    {
        if (strlen(argv[i]) >= 7 && strncasecmp(argv[i], "Nexus:", 7) == 0)
        {
            const char *strURI = argv[i];
            try {
                boost::interprocess::message_queue mq(boost::interprocess::open_only, NEXUS_URI_QUEUE_NAME);
                if(mq.try_send(strURI, strlen(strURI), 0))
                    exit(0);
                else
                    break;
            }
            catch (boost::interprocess::interprocess_exception &ex) {
                break;
            }
        }
    }
#endif
    
    // Internal string conversion is all UTF-8
//    QTextCodec::setCodecForTr(QTextCodec::codecForName("UTF-8"));
//    QTextCodec::setCodecForCStrings(QTextCodec::codecForTr());

    Q_INIT_RESOURCE(nexus);
    QApplication app(argc, argv);

    // Terms and Conditions
    QDir dir;
    QString termsPath;
    termsPath.append(GetDefaultDataDir().string().c_str());
    termsPath.append("/.license");
    QFile file(termsPath);

    if (!file.exists())
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Terms and Conditions");
        msgBox.setText("Please read and accept the terms and conditions:");
        msgBox.setInformativeText(
        "THE NEXUS EMBASSY HAS NOT DEVELOPED OR CREATED THE SOFTWARE USED IN THIS WALLET."
        "THE SOFTWARE WAS CREATED ON AN OPEN SOURCED BASIS BY MEMBERS OF THE COMMUNITY.  DUE TO THIS, "
        "THE NEXUS EMBASSY DOES NOT SPECIFICALLY ENDORSE THIS WALLET AND PLEASE USE AT YOUR OWN RISK. "
        "THE USE OF THIS WALLET, AS WELL AS ANY WALLET MAY RESULT IN THE LOSS OF YOUR TOKENS. "
        "USE AT YOUR OWN RISK.\n\n"
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING "
        "BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND "
        "NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, "
        "DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, "
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.");

        msgBox.setStandardButtons(QMessageBox::Cancel | QMessageBox::Ok);
        int ret = msgBox.exec();

        switch (ret) {
            case QMessageBox::Cancel:
            {
                //Exit
                return 0;
            }
            case QMessageBox::Ok:
            {
                if (file.open(QIODevice::ReadWrite))
                {

                }
		#if defined(WIN32)
                LPCWSTR licenseFile = (const wchar_t*) termsPath.utf16();
                int attr = GetFileAttributes(licenseFile);
                SetFileAttributes(licenseFile, attr | FILE_ATTRIBUTE_HIDDEN);
                #endif
            }
            default:
            // should never be reached
                break;
        }
    }
    
    
    
    QSplashScreen splash(QPixmap(":/images/splash"), 0);
    if (GetBoolArg("-splash", true) && !GetBoolArg("-min"))
    {
        splash.show();
        splash.setAutoFillBackground(true);
        splashref = &splash;
    }

    // Command-line options take precedence:
    ParseParameters(argc, argv);

    // ... then nexus.conf:
    if (!boost::filesystem::is_directory(GetDataDir(false)))
    {
        fprintf(stderr, "Error: Specified directory does not exist\n");
        return 1;
    }
    ReadConfigFile(mapArgs, mapMultiArgs);

    // Application identification (must be set before OptionsModel is initialized,
    // as it is used to locate QSettings)
    app.setOrganizationName("Nexus");
    app.setOrganizationDomain("nexusoft.io");
    if(GetBoolArg("-testnet", false)) // Separate UI settings for testnet
        app.setApplicationName("Nexus-testnet");
    else
        app.setApplicationName("Nexus");

    // ... then GUI settings:
    OptionsModel optionsModel;

    // Get desired locale ("en_US") from command line or system locale
    QString lang_territory = QString::fromStdString(GetArg("-lang", QLocale::system().name().toStdString()));
    // Load language files for configured locale:
    // - First load the translator for the base language, without territory
    // - Then load the more specific locale translator
    QString lang = lang_territory;

    lang.truncate(lang_territory.lastIndexOf('_')); // "en"
    QTranslator qtTranslatorBase, qtTranslator, translatorBase, translator;

    qtTranslatorBase.load(QLibraryInfo::location(QLibraryInfo::TranslationsPath) + "/qt_" + lang);
    if (!qtTranslatorBase.isEmpty())
        app.installTranslator(&qtTranslatorBase);

    qtTranslator.load(QLibraryInfo::location(QLibraryInfo::TranslationsPath) + "/qt_" + lang_territory);
    if (!qtTranslator.isEmpty())
        app.installTranslator(&qtTranslator);

    translatorBase.load(":/translations/"+lang);
    if (!translatorBase.isEmpty())
        app.installTranslator(&translatorBase);

    translator.load(":/translations/"+lang_territory);
    if (!translator.isEmpty())
        app.installTranslator(&translator);

    app.processEvents();

    app.setQuitOnLastWindowClosed(false);

    try
    {
        NexusGUI window;
        guiref = &window;
        if(AppInit2(argc, argv))
        {
            {
                // Put this in a block, so that the Model objects are cleaned up before
                // calling Shutdown().
                optionsModel.Upgrade(); // Must be done after AppInit2

                if (splashref)
                    splash.finish(&window);

                ClientModel clientModel(&optionsModel);
                clientmodel = &clientModel;
                WalletModel walletModel(pwalletMain, &optionsModel);
                walletmodel = &walletModel;

                window.setClientModel(&clientModel);
                window.setWalletModel(&walletModel);

                // If -min option passed, start window minimized.
                if(GetBoolArg("-min"))
                {
                    window.showMinimized();
                }
                else
                {
                    window.show();
                }

                // Place this here as guiref has to be defined if we dont want to lose URIs
                ipcInit();

#if !defined(MAC_OSX) && !defined(WIN32)
// TODO: implement qtipcserver.cpp for Mac and Windows

                // Check for URI in argv
                for (int i = 1; i < argc; i++)
                {
                    if (strlen(argv[i]) >= 7 && strncasecmp(argv[i], "Nexus:", 7) == 0)
                    {
                        const char *strURI = argv[i];
                        try {
                            boost::interprocess::message_queue mq(boost::interprocess::open_only, NEXUS_URI_QUEUE_NAME);
                            mq.try_send(strURI, strlen(strURI), 0);
                        }
                        catch (boost::interprocess::interprocess_exception &ex) {
                        }
                    }
                }
#endif
                app.exec();

                window.hide();
                window.setClientModel(0);
                window.setWalletModel(0);
                guiref = 0;
                clientmodel = 0;
                walletmodel = 0;
            }
            // Shutdown the core and it's threads, but don't exit Nexus-Qt here
            Shutdown(NULL);
        }
        else
        {
            return 1;
        }
    } catch (std::exception& e) {
        handleRunawayException(&e);
    } catch (...) {
        handleRunawayException(NULL);
    }
    return 0;
}
#endif // NEXUS_QT_TEST

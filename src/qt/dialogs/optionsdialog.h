/*******************************************************************************************

            Hash(BEGIN(Satoshi[2010]), END(W.J.[2012])) == Videlicet[2014] ++

 [Learn and Create] Viz. http://www.opensource.org/licenses/mit-license.php

*******************************************************************************************/

#ifndef OPTIONSDIALOG_H
#define OPTIONSDIALOG_H

#include <QtGlobal>
#if QT_VERSION < QT_VERSION_CHECK(5,0,0)
 #include <QDialog>
#else
 #include <QtWidgets/QDialog>
#endif

QT_BEGIN_NAMESPACE
class QStackedWidget;
class QListWidget;
class QListWidgetItem;
class QPushButton;
QT_END_NAMESPACE
class OptionsModel;
class MainOptionsPage;
class DisplayOptionsPage;
class MonitoredDataMapper;

/** Preferences dialog. */
class OptionsDialog : public QDialog
{
    Q_OBJECT
public:
    explicit OptionsDialog(QWidget *parent=0);

    void setModel(OptionsModel *model);

signals:

public slots:
    /** Change the current page to \a index. */
    void changePage(int index);

private slots:
    void okClicked();
    void cancelClicked();
    void applyClicked();
    void enableApply();
    void disableApply();

private:
    QListWidget *contents_widget;
    QStackedWidget *pages_widget;
    OptionsModel *model;
    MonitoredDataMapper *mapper;
    QPushButton *apply_button;

    // Pages
    MainOptionsPage *main_page;
    DisplayOptionsPage *display_page;

    void setupMainPage();
};

#endif // OPTIONSDIALOG_H

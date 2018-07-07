/*******************************************************************************************

            Hash(BEGIN(Satoshi[2010]), END(W.J.[2012])) == Videlicet[2014] ++

 [Learn and Create] Viz. http://www.opensource.org/licenses/mit-license.php

*******************************************************************************************/

#ifndef QRCODEDIALOG_H
#define QRCODEDIALOG_H

#include <QtGlobal>
#if QT_VERSION < QT_VERSION_CHECK(5,0,0)
 #include <QDialog>
#else
 #include <QtWidgets/QDialog>
#endif
#include <QImage>

namespace Ui {
    class QRCodeDialog;
}

class QRCodeDialog : public QDialog
{
    Q_OBJECT

public:
    explicit QRCodeDialog(const QString &addr, const QString &label, bool enableReq, QWidget *parent = 0);
    ~QRCodeDialog();

private slots:
    void on_lnReqAmount_textChanged(const QString &arg1);
    void on_lnLabel_textChanged(const QString &arg1);
    void on_lnMessage_textChanged(const QString &arg1);
    void on_btnSaveAs_clicked();

    void on_chkReqPayment_toggled(bool checked);

private:
    Ui::QRCodeDialog *ui;
    QImage myImage;

    QString getURI();
    QString address;

    void genCode();
};

#endif // QRCODEDIALOG_H

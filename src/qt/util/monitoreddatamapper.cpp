/*******************************************************************************************

            Hash(BEGIN(Satoshi[2010]), END(W.J.[2012])) == Videlicet[2014] ++

 [Learn and Create] Viz. http://www.opensource.org/licenses/mit-license.php

*******************************************************************************************/

#include "monitoreddatamapper.h"
#if QT_VERSION < QT_VERSION_CHECK(5,0,0)
 #include <QWidget>
#else
 #include <QtWidgets/QWidget>
#endif


#include <QMetaObject>
#include <QMetaProperty>

MonitoredDataMapper::MonitoredDataMapper(QObject *parent) :
    QDataWidgetMapper(parent)
{
}


void MonitoredDataMapper::addMapping(QWidget *widget, int section)
{
    QDataWidgetMapper::addMapping(widget, section);
    addChangeMonitor(widget);
}

void MonitoredDataMapper::addMapping(QWidget *widget, int section, const QByteArray &propertyName)
{
    QDataWidgetMapper::addMapping(widget, section, propertyName);
    addChangeMonitor(widget);
}

void MonitoredDataMapper::addChangeMonitor(QWidget *widget)
{
    // Watch user property of widget for changes, and connect
    //  the signal to our viewModified signal.
    QMetaProperty prop = widget->metaObject()->userProperty();
    int signal = prop.notifySignalIndex();
    int method = this->metaObject()->indexOfMethod("viewModified()");
    if(signal != -1 && method != -1)
    {
        QMetaObject::connect(widget, signal, this, method);
    }
}

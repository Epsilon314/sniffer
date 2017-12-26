#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QComboBox>
#include <QTextBrowser>
#include <QWidget>
#include <QLayout>
#include <pcap.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "sniffer.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void findDev();
public slots:
    void startSniff();
    void pauseSniff();
    void clearSniff();
    void updateDev();
    void addCapList(Pkt_display pktdisplay);
    void displayPayload(int rowc);
private:
    Ui::MainWindow *ui;
    Sniffer_thread *snifferthread;
};

#endif // MAINWINDOW_H

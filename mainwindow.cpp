#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "sniffer.h"

const int PKTUPLIMIT = 2048;
Pkt_display buff[PKTUPLIMIT];

extern QString p_dev ;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    qRegisterMetaType<Pkt_display>("Pkt_display");
    qRegisterMetaType<Pkt_display>("Pkt_display&");
    ui->setupUi(this);
    snifferthread = new Sniffer_thread();
    ui->comboBox->setUpdatesEnabled(1);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    findDev();
    updateDev();
    connect(snifferthread,SIGNAL(pkt_info(Pkt_display)),this,
            SLOT(addCapList(Pkt_display)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::findDev()  {
    pcap_if_t *listDev;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(!pcap_findalldevs(&listDev,errbuf)) {
        for(device = listDev; device ; device = device->next) {
            ui->comboBox->addItem(QWidget::tr(device->name));
        }
    }
    else {
        ui->comboBox->addItem(QWidget::tr("Can't find any device."));
        exit(1);
    }
}

void MainWindow::updateDev() {
    p_dev = ui->comboBox->currentText();
}

void MainWindow::startSniff() {
    if (snifferthread->disactived()) {
        snifferthread->enable();
    }
    else {
        snifferthread->terminate();
        snifferthread->wait();
    }
    snifferthread->start();
}

void MainWindow::pauseSniff() {
    snifferthread->disable();
}

void MainWindow::clearSniff() {
    int rowC = ui->tableWidget->rowCount();
    for (int i = 0; i < rowC; i++) {
        ui->tableWidget->removeRow(0);
    }
}

void MainWindow::addCapList(Pkt_display pktdisplay) {
    ui->tableWidget->scrollToBottom();
    int rowC  = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(rowC);
    QTableWidgetItem *item_sip,*item_dip,*item_proto,*item_len;
    item_sip = new QTableWidgetItem(pktdisplay.sip);
    item_dip = new QTableWidgetItem(pktdisplay.dip);
    item_proto = new QTableWidgetItem(pktdisplay.proto);
    item_len = new QTableWidgetItem(pktdisplay.len);
    ui->tableWidget->setItem(rowC, 0, item_sip);
    ui->tableWidget->setItem(rowC, 1, item_dip);
    ui->tableWidget->setItem(rowC, 2, item_proto);
    ui->tableWidget->setItem(rowC, 3, item_len);
    buff[rowC] = pktdisplay;
}

void MainWindow::displayPayload(int rowc) {
    ui->textBrowser->clear();
    ui->textBrowser_2->clear();
    bool *ok;
    const int lineWidth = 16;
    const u_char* payload = buff[rowc].pktdata;
    int len = buff[rowc].len.toInt(ok);
    char display[8];
    for (int offset = 0; offset < len; offset++,payload++) {
        if(offset % lineWidth == 0 && offset != 0) {
            ui->textBrowser->insertPlainText("\n");
            ui->textBrowser_2->insertPlainText("\n");
        }
        sprintf(display,"%02x  ",*payload);
        ui->textBrowser->insertPlainText(display);
        if(isprint(*payload)) {
            sprintf(display,"%c",*payload);
            ui->textBrowser_2->insertPlainText(display);
        }
        else {
            ui->textBrowser_2->insertPlainText(".");
        }
    }
}

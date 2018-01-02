#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "sniffer.h"

const int PKTUPLIMIT = 80000;
Pkt_display buff[PKTUPLIMIT];
const char* p_path = "temp.pcap";
const QString q_path = QString("temp.pcap");

extern QString p_dev ;
extern QString p_filter;

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
    ui->tableWidget->setColumnWidth(0,170);
    ui->tableWidget->setColumnWidth(1,170);
    ui->tableWidget->setColumnWidth(2,100);
    ui->tableWidget->setColumnWidth(3,100);

    findDev();
    updateDev();

    connect(snifferthread,SIGNAL(pkt_info(Pkt_display)),this,
            SLOT(addCapList(Pkt_display)));
    connect(ui->tableWidget,SIGNAL(cellClicked(int,int)),this,SLOT(displayPayload(int,int)));
    connect(ui->tableWidget,SIGNAL(cellClicked(int,int)),this,SLOT(updatePktInfo(int,int)));
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
    MainWindow::updateCheckboxState();
    MainWindow::generateFilterExpression();
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
    if (pktdisplay.eth_proto == QString("IP")) {
        if(pktdisplay.ip_proto == QString("TCP")) {
            if (pktdisplay.trans_proto != QString("UNKNOWN")) {
                item_proto = new QTableWidgetItem(pktdisplay.trans_proto);
            }
            else {
                item_proto = new QTableWidgetItem(pktdisplay.ip_proto);
            }
        }
        else {
            item_proto = new QTableWidgetItem(pktdisplay.ip_proto);
        }
    }
    else {
        item_proto = new QTableWidgetItem(pktdisplay.eth_proto);
    }
    item_len = new QTableWidgetItem(pktdisplay.len);

    if(pktdisplay.eth_proto == QString("ARP")) {
        item_sip->setBackgroundColor(QColor(200,150,120));
        item_dip->setBackgroundColor(QColor(200,150,120));
        item_proto->setBackgroundColor(QColor(200,150,120));
        item_len->setBackgroundColor(QColor(200,150,120));
    }
    if(pktdisplay.eth_proto == QString("RARP")) {
        item_sip->setBackgroundColor(QColor(200,150,150));
        item_dip->setBackgroundColor(QColor(200,150,150));
        item_proto->setBackgroundColor(QColor(200,150,150));
        item_len->setBackgroundColor(QColor(200,150,150));
    }
    if(pktdisplay.eth_proto == QString("IPv6")) {
        item_sip->setBackgroundColor(QColor(160,150,180));
        item_dip->setBackgroundColor(QColor(160,150,180));
        item_proto->setBackgroundColor(QColor(160,150,180));
        item_len->setBackgroundColor(QColor(160,150,180));
    }
    if(pktdisplay.eth_proto == QString("PPPoE")) {
        item_sip->setBackgroundColor(QColor(100,200,120));
        item_dip->setBackgroundColor(QColor(100,200,120));
        item_proto->setBackgroundColor(QColor(100,200,120));
        item_len->setBackgroundColor(QColor(100,200,120));
    }
    if(pktdisplay.ip_proto == QString("TCP")
            && pktdisplay.eth_proto == QString("IP")) {
        item_sip->setBackgroundColor(QColor(100,150,200));
        item_dip->setBackgroundColor(QColor(100,150,200));
        item_proto->setBackgroundColor(QColor(100,150,200));
        item_len->setBackgroundColor(QColor(100,150,200));
    }
    if(pktdisplay.ip_proto == QString("UDP")
            && pktdisplay.eth_proto == QString("IP")) {
        item_sip->setBackgroundColor(QColor(200,200,80));
        item_dip->setBackgroundColor(QColor(200,200,80));
        item_proto->setBackgroundColor(QColor(200,200,80));
        item_len->setBackgroundColor(QColor(200,200,80));
    }
    if(pktdisplay.ip_proto == QString("ICMP")
            && pktdisplay.eth_proto == QString("IP")) {
        item_sip->setBackgroundColor(QColor(250,150,120));
        item_dip->setBackgroundColor(QColor(250,150,120));
        item_proto->setBackgroundColor(QColor(250,150,120));
        item_len->setBackgroundColor(QColor(250,150,120));
    }
    if(pktdisplay.ip_proto == QString("IGMP")
            && pktdisplay.eth_proto == QString("IP")) {
        item_sip->setBackgroundColor(QColor(200,150,250));
        item_dip->setBackgroundColor(QColor(200,150,250));
        item_proto->setBackgroundColor(QColor(200,150,250));
        item_len->setBackgroundColor(QColor(200,150,250));
    }
    if(pktdisplay.trans_proto == QString("HTTP")
            && pktdisplay.ip_proto == QString("TCP")) {
        item_sip->setBackgroundColor(QColor(120,250,250));
        item_dip->setBackgroundColor(QColor(120,250,250));
        item_proto->setBackgroundColor(QColor(120,250,250));
        item_len->setBackgroundColor(QColor(120,250,250));
    }
    if(pktdisplay.trans_proto == QString("FTP")
            && pktdisplay.ip_proto == QString("TCP")) {
        item_sip->setBackgroundColor(QColor(200,50,250));
        item_dip->setBackgroundColor(QColor(200,50,250));
        item_proto->setBackgroundColor(QColor(200,50,250));
        item_len->setBackgroundColor(QColor(200,50,250));
    }
    if(pktdisplay.trans_proto == QString("TELNET")
            && pktdisplay.ip_proto == QString("TCP")) {
        item_sip->setBackgroundColor(QColor(220,110,200));
        item_dip->setBackgroundColor(QColor(220,110,200));
        item_proto->setBackgroundColor(QColor(220,110,200));
        item_len->setBackgroundColor(QColor(220,110,200));
    }
    if(pktdisplay.trans_proto == QString("SMTP")
            && pktdisplay.ip_proto == QString("TCP")) {
        item_sip->setBackgroundColor(QColor(180,230,180));
        item_dip->setBackgroundColor(QColor(180,230,180));
        item_proto->setBackgroundColor(QColor(180,230,180));
        item_len->setBackgroundColor(QColor(180,230,180));
    }
    if(pktdisplay.trans_proto == QString("DNS")
            && pktdisplay.ip_proto == QString("TCP")) {
        item_sip->setBackgroundColor(QColor(180,180,220));
        item_dip->setBackgroundColor(QColor(180,180,220));
        item_proto->setBackgroundColor(QColor(180,180,220));
        item_len->setBackgroundColor(QColor(180,180,220));
    }
    if(pktdisplay.trans_proto == QString("POP3")
            && pktdisplay.ip_proto == QString("TCP")) {
        item_sip->setBackgroundColor(QColor(200,180,250));
        item_dip->setBackgroundColor(QColor(200,180,250));
        item_proto->setBackgroundColor(QColor(200,180,250));
        item_len->setBackgroundColor(QColor(200,180,250));
    }
    if(pktdisplay.trans_proto == QString("HTTPS")
            && pktdisplay.ip_proto == QString("TCP")) {
        item_sip->setBackgroundColor(QColor(250,120,250));
        item_dip->setBackgroundColor(QColor(250,120,250));
        item_proto->setBackgroundColor(QColor(250,120,250));
        item_len->setBackgroundColor(QColor(250,120,250));
    }

    ui->tableWidget->setItem(rowC, 0, item_sip);
    ui->tableWidget->setItem(rowC, 1, item_dip);
    ui->tableWidget->setItem(rowC, 2, item_proto);
    ui->tableWidget->setItem(rowC, 3, item_len);
    buff[rowC] = pktdisplay;

}

void MainWindow::displayPayload(int rowc,int) {
    ui->textBrowser->clear();
    ui->textBrowser_2->clear();

    bool ok = true;
    const int lineWidth = 16;
    const u_char* payload = buff[rowc].pktdata;
    int len = buff[rowc].len.toInt(&ok);
    char display[20];
    for (int offset = 0; offset < len; offset++) {
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
        payload ++;
    }
}

void MainWindow::updateCheckboxState() {
    if(ui->checkBox->checkState() == Qt::Checked) {
        snifferthread->set_mode_reassamble(true);
    }
    else {
        snifferthread->set_mode_reassamble(false);
    }
}

void MainWindow::updatePktInfo(int rowc,int) {
    ui->textBrowser_3->clear();

    Pkt_display pkt = buff[rowc];

    QString devInfo = QString("Interface:%1 Length:%2").arg(p_dev).arg(pkt.len);
    QString ethInfo = QString("Source MAC %1\nDestination MAC %2\nETHERNET Type: %3")
            .arg(pkt.smac).arg(pkt.dmac).arg(pkt.eth_proto);
    QString ipInfo = QString("%1").arg(pkt.trans_proto);
    QString tcpInfo = QString("SourcePort:%1 DestinationPort:%2").arg(pkt.sport).arg(pkt.dport);

    ui->textBrowser_3->insertPlainText(devInfo);
    ui->textBrowser_3->insertPlainText("\n");
    ui->textBrowser_3->insertPlainText(ethInfo);
    if (pkt.eth_proto == QString("IP")) {
        if(ipInfo != QString("UNKNOWN")) {
            ui->textBrowser_3->insertPlainText("\n");
            ui->textBrowser_3->insertPlainText(ipInfo);
        }
        if(pkt.ip_proto == QString("TCP")) {
            ui->textBrowser_3->insertPlainText("\n");
            ui->textBrowser_3->insertPlainText(tcpInfo);
        }
    }
}

void MainWindow::generateFilterExpression() {
    p_filter = QString("");
    if(ui->lineEdit_5->text() != QString("")) {
        p_filter = ui->lineEdit_6->text();
    }
    else {
        if(ui->lineEdit->text() != QString("")) {
            p_filter = p_filter + QString("%1 ").arg(ui->lineEdit->text());
        }
        if(ui->lineEdit_2->text() != QString("")) {
            if(p_filter != QString("")) {
                p_filter = p_filter + QString("and ");
            }
            p_filter = p_filter + QString("src host %1 ").arg(ui->lineEdit_2->text());
        }
        if(ui->lineEdit_3->text() != QString("")) {
            if(p_filter != QString("")) {
                p_filter = p_filter + QString("and ");
            }
            p_filter = p_filter + QString("dst host %1 ").arg(ui->lineEdit_3->text());
        }
        if(ui->lineEdit_4->text() != QString("")) {
            if(p_filter != QString("")) {
                p_filter = p_filter + QString("and ");
            }
            p_filter = p_filter + QString("src port %1 ").arg(ui->lineEdit_4->text());
        }
        if(ui->lineEdit_5->text() != QString("")) {
            if(p_filter != QString("")) {
                p_filter = p_filter + QString("and ");
            }
            p_filter = p_filter + QString("dst host %1 ").arg(ui->lineEdit_5->text());
        }
    }
    printf("%s\n",p_filter.toStdString().c_str());
}

void MainWindow::saveFileDiag() {
    snifferthread->saveDump();
    QFileDialog *diag = new QFileDialog(this);
    diag->setWindowTitle("Save as");
    diag->setAcceptMode(QFileDialog::AcceptSave);
    diag->setFileMode(QFileDialog::AnyFile);
    diag->setViewMode(QFileDialog::Detail);
    QString path = QFileDialog::getSaveFileName(this,tr("Open File"),".",tr("Text Files(*.pcap)"));
    if (!QFile::copy(q_path,path)) {
        QMessageBox::warning(this, tr("Write File"),
                             tr("Can't open file:\n%1").arg(path));
    }
    /*
    if(!path.isEmpty()) {
        QFile file(path);
        if(!file.open(QIODevice::WriteOnly)){
            QMessageBox::warning(this, tr("Write File"),
                                 tr("Can't open file:\n%1").arg(path));
            return;
        }
        QFile dump(q_path);
        dump.open(QIODevice::ReadOnly);


        file.close();
    }
    else {
        QMessageBox::warning(this, tr("Path"),
                             tr("You did not select any file."));
    }
    */
}

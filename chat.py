#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
import sys
import os

from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QMessageBox, QLabel, QLineEdit, QTextEdit, QRadioButton, QButtonGroup, QScrollArea, QScrollBar)
from PyQt5.QtGui import (QFont)
from PyQt5.QtCore import Qt, pyqtSignal

from socket import *
from datetime import datetime
from time import time, sleep
import threading
import re
import random
import json

class defaultButton(QPushButton):
    def __init__(self, parents):
        super().__init__(parents)
        self.setStyleSheet("QPushButton{color:black; background-color:rgb(220, 220, 220)}"
                        "QPushButton:hover{border:2px solid grey}"
                        "QPushButton:pressed{background-color:rgb(100, 100, 100); color:white}"
                        "QPushButton{border:1px solid grey; border-radius:6px}")

class defaultLine(QLineEdit):
    def __init__(self, parents):
        super().__init__(parents)
        self.setFont(QFont("SansSerif", 12))
        self.setAlignment(Qt.AlignCenter)
        self.setAttribute(Qt.WA_MacShowFocusRect, 0)
        self.setStyleSheet("QLineEdit{border-radius:10px; padding:2px 2px}")

# 登陆界面
class mainWidgets(QWidget):
    signal = pyqtSignal([int, dict])
    historyNum = 0
    def __init__(self):
        super().__init__()
        self.initUI()
        self.state = 'stopped'
        self.type = 'udp'
        self.threads = None
        self.server = None
        self.connection = None
        
    def initUI(self):
        self.setWindowFlags(Qt.WindowCloseButtonHint)
        self.setFixedSize(600, 360)
        self.setWindowTitle('Let\'s chat!')
        
        self.label1 = QLabel(self)
        self.label1.setText('remote IP:')
        self.label1.setFont(QFont("SansSerif", 12))
        self.label1.setGeometry(35, 30, 60, 16)

        self.remoteIPLine = defaultLine(self)
        self.remoteIPLine.setText('127.0.0.1')
        self.remoteIPLine.setGeometry(105, 28, 120, 20)
        
        self.label2 = QLabel(self)
        self.label2.setText('remote port:')
        self.label2.setFont(QFont("SansSerif", 12))
        self.label2.setGeometry(245, 30, 80, 16)

        self.remotePortLine = defaultLine(self)
        self.remotePortLine.setGeometry(325, 28, 60, 20)
        
        self.udpBt = QRadioButton(self)
        self.udpBt.setText("udp")
        self.udpBt.setFont(QFont("SansSerif", 12))
        self.udpBt.setGeometry(405, 28, 60, 20)
        self.udpBt.setChecked(True)

        self.udpBindBt = defaultButton(self)
        self.udpBindBt.setText('bind')
        self.udpBindBt.setFont(QFont("SansSerif", 12))
        self.udpBindBt.setGeometry(455, 28, 50, 20)
        
        self.udpLabel = QLabel(self)
        self.udpLabel.setText('stopped')
        self.udpLabel.setFont(QFont("SansSerif", 12))
        self.udpLabel.setGeometry(510, 30, 60, 16)

        self.label3 = QLabel(self)
        self.label3.setText('nickname:')
        self.label3.setFont(QFont("SansSerif", 12))
        self.label3.setGeometry(35, 65, 60, 16)

        self.playerLine = defaultLine(self)
        self.playerLine.setGeometry(105, 63, 120, 20)

        self.label4 = QLabel(self)
        self.label4.setText('local port:')
        self.label4.setFont(QFont("SansSerif", 12))
        self.label4.setGeometry(249, 65, 80, 16)

        self.localPortLine = defaultLine(self)
        self.localPortLine.setText(str(random.randint(1025, 65535)))
        self.localPortLine.setGeometry(325, 63, 60, 20)

        self.tcpBt = QRadioButton(self)
        self.tcpBt.setText("tcp")
        self.tcpBt.setFont(QFont("SansSerif", 12))
        self.tcpBt.setGeometry(405, 63, 40, 20)

        self.tcpBindBt = defaultButton(self)
        self.tcpBindBt.setText('bind')
        self.tcpBindBt.setFont(QFont("SansSerif", 12))
        self.tcpBindBt.setGeometry(455, 63, 50, 20)
        self.tcpBindBt.setVisible(False)

        self.connectBt = defaultButton(self)
        self.connectBt.setText('connect')
        self.connectBt.setFont(QFont("SansSerif", 12))
        self.connectBt.setGeometry(510, 63, 50, 20)
        self.connectBt.setVisible(False)

        self.tcpLabel = QLabel(self)
        self.tcpLabel.setFont(QFont("SansSerif", 12))
        self.tcpLabel.setVisible(False)

        self.btGroup = QButtonGroup(self)
        self.btGroup.addButton(self.udpBt)
        self.btGroup.addButton(self.tcpBt)

        self.historyWidget = QWidget(self)
        self.historyWidget.setStyleSheet('background-color:#ffffff;')
        self.historyWidget.setGeometry(80, 100, 436, 0)

        self.scroll = QScrollArea(self)
        self.scroll.setStyleSheet('QScrollArea{border: 0px; background-color:#ffffff; border-radius:10px; padding:2px 2px}')
        self.scroll.setGeometry(80, 100, 440, 200)

        self.scroll.setWidget(self.historyWidget)

        self.messageLine = defaultLine(self)
        self.messageLine.setGeometry(120, 320, 240, 20)

        self.clearBt = defaultButton(self)
        self.clearBt.setText('clear')
        self.clearBt.setFont(QFont("SansSerif", 12))
        self.clearBt.setGeometry(390, 320, 40, 20)

        self.sendBt = defaultButton(self)
        self.sendBt.setText('send')
        self.sendBt.setFont(QFont("SansSerif", 12))
        self.sendBt.setGeometry(450, 320, 40, 20)

        self.udpBt.clicked.connect(self.slot_selectUDPMode)
        self.tcpBt.clicked.connect(self.slot_selectTCPMode)
        self.udpBindBt.clicked.connect(self.slot_Bind)
        self.tcpBindBt.clicked.connect(self.slot_Bind)
        self.clearBt.clicked.connect(self.slot_clear)
        self.sendBt.clicked.connect(self.slot_send)
        self.connectBt.clicked.connect(self.slot_connect)
        
        self.signal.connect(self.slot_signalHandler)

        self.show()
    
    def slot_selectUDPMode(self):
        self.state = 'stopped'
        self.type = 'udp'
        self.udpBindBt.setVisible(True)
        self.udpLabel.setVisible(True)
        self.tcpBindBt.setText('bind')
        self.tcpBindBt.setVisible(False)
        self.tcpLabel.setVisible(False)
        self.connectBt.setVisible(False)
        print('select udp mode')


    def slot_selectTCPMode(self):
        self.state = 'stopped'
        self.type = 'tcp'
        self.udpLabel.setText('stopped')
        self.udpBindBt.setText('bind')
        self.udpBindBt.setVisible(False)
        self.udpLabel.setVisible(False)
        self.tcpBindBt.setVisible(True)
        self.connectBt.setVisible(True)
        print('select tcp mode')

    def slot_Bind(self):
        if self.state == 'stopped':
            if self.localPortLine.text().isdigit() == False:
                QMessageBox.warning(self, 'Error', 'local port is invalid!\n(1025~65535)')
                return
            
            localPort = int(self.localPortLine.text())
            if  localPort <= 1024 or localPort > 65535:
                QMessageBox.warning(self, 'Error', 'please use the free local port!\n(1025~65535)')
                return

            self.state = 'listening'
            self.threads = threading.Thread(target=self.listen, args=(localPort,), daemon=True)
            self.threads.start()

        elif self.state == 'listening' or self.state == 'connecting':
            self.state = 'stopped'

    def listen(self, port):
        if self.type == 'udp':
            udp = threading.Thread(target=self.udp_setup, args=('0.0.0.0', port), daemon=True)
            udp.start()
            self.udpLabel.setText('listeing')
            self.udpBindBt.setText('release')

        elif self.type == 'tcp':
            tcp = threading.Thread(target=self.tcp_setup, args=('0.0.0.0', port), daemon=True)
            tcp.start()
            self.connectBt.setVisible(False)
            self.tcpLabel.setText('listening')
            self.tcpLabel.setGeometry(510, 65, 60, 16)
            self.tcpLabel.setVisible(True)
            self.tcpBindBt.setText('release')

        else:
            self.state = 'stopped'
            self.server = None
            self.connection = None
            return

        while True:
            if self.state == 'stopped':
                if self.server != None:
                    self.server.close()
                if self.type == 'udp':
                    self.udpLabel.setText('stopped')
                    self.udpBindBt.setText('bind')
                elif self.type == 'tcp':
                    self.udpBindBt.setVisible(False)
                    self.udpLabel.setVisible(False)
                    self.tcpBindBt.setText('bind')
                    self.connectBt.setVisible(True)
                    self.tcpLabel.setVisible(False)
                print('listen stopped')
                break

    def udp_setup(self, ip, port):
        try:
            self.server = socket(AF_INET, SOCK_DGRAM)
            self.server.bind((ip, port))
            print('udp listening (localhost, ' + str(port) + ')')
        except:
            self.state = 'stopped'
            self.signal[int, dict].emit(1, {})
            return
        else:
            try:
                while True:
                    data, addr = self.server.recvfrom(1024) 
                    try:
                        dic = json.loads(data.decode('utf-8'))
                    except:
                        print('udp server get data which is not json format!')
                    else:
                        history = threading.Thread(target=self.signal_recvMsg, args=(dic,))
                        history.start()
            except:
                if self.server == None:
                    print('udp server is closed')
                else:
                    print('revieve data wrong')
            else:
                self.server.close()
    
    def tcp_setup(self, ip, port):
        if self.state == 'listening':
            try:
                self.server = socket(AF_INET, SOCK_STREAM)
                self.server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                self.server.bind((ip, port))
                self.server.listen(1)
                print('tcp listening (localhost, ' + str(port) + ')')
            except:
                self.state = 'stopped'
                self.signal[int, dict].emit(1, {})
                return
            else:
                while True:
                    try:
                        self.connection, address = self.server.accept()
                    except:
                        print('the connection is closed')
                        break
                    else:
                        self.tcpLabel.setText('success')
                        t = threading.Thread(target=self.tcp_recv, args=(self.connection,))
                        t.start()

        elif self.state == 'connecting':
            try:
                self.connection = socket(AF_INET, SOCK_STREAM)
                self.connection.connect((ip, port))
                print('tcp connected with (localhost, ' + str(port) + ')')
            except:
                self.state = 'stopped'
                self.signal[int, dict].emit(1, {})
                return
            else:
                self.signal[int, dict].emit(4, {})
                t = threading.Thread(target=self.tcp_recv, args=(self.connection,))
                t.start()

    def tcp_recv(self, connection):
        while True: 
            try:
                data = connection.recv(1024)
                try:
                    dic = json.loads(data.decode('utf-8'))
                except:
                    print('tcp server get data which is not json format!')
                else:
                    history = threading.Thread(target=self.signal_recvMsg, args=(dic,))
                    history.start()   
            except:
                print('the connection is close!')
                break

        connection.close()

    def signal_recvMsg(self, dic):
        self.signal[int, dict].emit(2, dic)

    def slot_clear(self):
        self.historyNum = 0
        self.messageLine.setText('')
        self.historyWidget.deleteLater()
        self.historyWidget = QWidget(self)
        self.historyWidget.setStyleSheet('background-color:#ffffff;')
        self.historyWidget.setGeometry(80, 100, 436, 0)
        self.scroll.setWidget(self.historyWidget)

    def slot_connect(self):
        if self.state == 'stopped':
            remoteIP = self.remoteIPLine.text()
            valid = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", remoteIP)
            
            if valid == None:
                QMessageBox.warning(self, 'Error', 'remote ip is invalid!')
                return
            
            if self.remotePortLine.text().isdigit() == False:
                QMessageBox.warning(self, 'Error', 'remote port is invalid!\n(1025~65535)')
                return
            
            remotePort = int(self.remotePortLine.text())
            if  remotePort <= 1024 or remotePort > 65535:
                QMessageBox.warning(self, 'Error', 'please use the free remote port!\n(1025~65535)')
                return

            self.state = 'connecting'
            tcp = threading.Thread(target=self.tcp_setup, args=(remoteIP, remotePort), daemon=True)
            tcp.start()

        elif self.state == 'connecting' or self.state == 'listening':
            self.state = 'stopped'
            if self.connection != None:
                self.connection.close()
                if self.server != None:
                    self.server.close()
            self.tcpLabel.setVisible(False)
            self.tcpBindBt.setVisible(True)
            self.connectBt.setVisible(True)

    def slot_send(self):
        player = self.playerLine.text()
        message = self.messageLine.text()
        time_ = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        package = {'player': player, 'message': message, 'time': time_}

        if self.type == 'udp':
            remoteIP = self.remoteIPLine.text()
            valid = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", remoteIP)
            
            if valid == None:
                QMessageBox.warning(self, 'Error', 'remote ip is invalid!')
                return
            
            if self.remotePortLine.text().isdigit() == False:
                QMessageBox.warning(self, 'Error', 'remote port is invalid!\n(1025~65535)')
                return
            
            remotePort = int(self.remotePortLine.text())
            if  remotePort <= 1024 or remotePort > 65535:
                QMessageBox.warning(self, 'Error', 'please use the free remote port!\n(1025~65535)')
                return

            send = threading.Thread(target=self.udp_send, args=(remoteIP, remotePort, package))
            send.start()

        elif self.type == 'tcp':
            if self.state != 'listening' and self.state != 'connecting':
                QMessageBox.warning(self, 'Error', 'No connection yet!')
                return
            send = threading.Thread(target=self.tcp_send, args=(package,))
            send.start()

        self.messageLine.setText('')

    def udp_send(self, ip, port, dic):
        data = json.dumps(dic)
        try:
            udp = socket(AF_INET, SOCK_DGRAM)
            udp.sendto(data.encode('utf-8'), (ip, port))
        except:
            print('can\'t send the message!')
        else:
            udp.close()
            self.signal[int, dict].emit(3, dic)

    def tcp_send(self, dic):
        data = json.dumps(dic)
        try:
            self.connection.send(data.encode('utf-8'))
        except:
            print('can\'t send the message!')
            self.signal[int, dict].emit(5, {})
        else:
            self.signal[int, dict].emit(3, dic)

    def slot_signalHandler(self, type, dic):
        if type == 1:
            QMessageBox.warning(self, 'Error', 'setup a ' + self.type +' server failed!')
        elif type == 2:
            player = dic['player']
            time_ = dic['time']
            message = dic['message']
            if (player == ''):
                player = 'someone'

            self.historyWidget.setGeometry(0, 0, 436, self.historyNum * 50 + 50)
            self.recvName = QLabel(self.historyWidget)
            self.recvName.setText(player + ' says:')
            self.recvName.setGeometry(10, self.historyNum * 50 + 6, 120, 16)
            self.recvName.setVisible(True)
            self.recvMsg = QLabel(self.historyWidget)
            self.recvMsg.setText(message)
            self.recvMsg.setGeometry(10, self.historyNum * 50 + 28, 200, 16)
            self.recvMsg.setVisible(True)
            self.historyNum = self.historyNum + 1

            if self.udpBt.isChecked() == True:
                self.type = 'udp'
            elif self.tcpBt.isChecked() == True:
                self.type = 'tcp'

        elif type == 3:
            player = dic['player']
            time_ = dic['time']
            message = dic['message']
            if (player == ''):
                player = 'you'

            self.historyWidget.setGeometry(0, 0, 436, self.historyNum * 50 + 50)
            self.recvName = QLabel(self.historyWidget)
            self.recvName.setText(player + ' says:')
            self.recvName.setGeometry(300, self.historyNum * 50 + 6, 120, 16)
            self.recvName.setVisible(True)
            self.recvMsg = QLabel(self.historyWidget)
            self.recvMsg.setText(message)
            self.recvMsg.setGeometry(300, self.historyNum * 50 + 28, 200, 16)
            self.recvMsg.setVisible(True)
            self.historyNum = self.historyNum + 1

            if self.udpBt.isChecked() == True:
                self.type = 'udp'
            elif self.tcpBt.isChecked() == True:
                self.type = 'tcp'

        elif type == 4:
            self.tcpBindBt.setVisible(False)
            self.tcpLabel.setText('success')
            self.tcpLabel.setGeometry(455, 65, 60, 16)
            self.tcpLabel.setVisible(True)
            self.connectBt.setText('cancle')
        
        elif type == 5:
            QMessageBox.warning(self, 'Error', 'the connection is close!')
            self.state = 'stopped'
            self.tcpLabel.setVisible(False)
            self.tcpBindBt.setVisible(True)
            self.connectBt.setVisible(True)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()

        elif event.key() == Qt.Key_Return:
            self.slot_send()


def main():
    app = QApplication(sys.argv)
    m = mainWidgets()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
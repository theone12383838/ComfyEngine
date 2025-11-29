#include "gui/ValueMonitorDialog.h"

#include "core/TargetProcess.h"
#include "core/MemoryScanner.h"

#include <QVBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QTimer>

ValueMonitorDialog::ValueMonitorDialog(core::TargetProcess *proc,
                                       uintptr_t address,
                                       core::ValueType type,
                                       QWidget *parent)
    : QDialog(parent), proc_(proc), address_(address), type_(type) {
    setWindowTitle("Value Change Monitor");
    auto *layout = new QVBoxLayout(this);

    header_ = new QLabel(this);
    header_->setText(QString("Address: 0x%1").arg(static_cast<unsigned long long>(address_), 0, 16));
    layout->addWidget(header_);

    table_ = new QTableWidget(this);
    table_->setColumnCount(3);
    table_->setHorizontalHeaderLabels({"#", "Old", "New"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table_);

    timer_ = new QTimer(this);
    timer_->setInterval(100);
    connect(timer_, &QTimer::timeout, this, &ValueMonitorDialog::poll);
    lastBytes_ = readCurrent();
    timer_->start();
}

QByteArray ValueMonitorDialog::readCurrent() const {
    if (!proc_) return {};
    int size = 0;
    switch (type_) {
        case core::ValueType::Byte: size = sizeof(int8_t); break;
        case core::ValueType::Int16: size = sizeof(int16_t); break;
        case core::ValueType::Int32: size = sizeof(int32_t); break;
        case core::ValueType::Int64: size = sizeof(int64_t); break;
        case core::ValueType::Float: size = sizeof(float); break;
        case core::ValueType::Double: size = sizeof(double); break;
        case core::ValueType::ArrayOfByte:
        case core::ValueType::String:
            size = 8;
            break;
    }
    QByteArray bytes(size, 0);
    if (!proc_->readMemory(address_, bytes.data(), static_cast<size_t>(size))) {
        return {};
    }
    return bytes;
}

void ValueMonitorDialog::poll() {
    QByteArray current = readCurrent();
    if (current.isEmpty() || current == lastBytes_) return;

    auto formatVal = [this](const QByteArray &b) -> QString {
        if (b.isEmpty()) return QString();
        switch (type_) {
            case core::ValueType::Byte: {
                int8_t v;
                std::memcpy(&v, b.constData(), sizeof(v));
                return QString::number(v);
            }
            case core::ValueType::Int16: {
                int16_t v;
                std::memcpy(&v, b.constData(), sizeof(v));
                return QString::number(v);
            }
            case core::ValueType::Int32: {
                int32_t v;
                std::memcpy(&v, b.constData(), sizeof(v));
                return QString::number(v);
            }
            case core::ValueType::Int64: {
                int64_t v;
                std::memcpy(&v, b.constData(), sizeof(v));
                return QString::number(v);
            }
            case core::ValueType::Float: {
                float v;
                std::memcpy(&v, b.constData(), sizeof(v));
                return QString::number(v, 'g', 6);
            }
            case core::ValueType::Double: {
                double v;
                std::memcpy(&v, b.constData(), sizeof(v));
                return QString::number(v, 'g', 12);
            }
            case core::ValueType::ArrayOfByte:
            case core::ValueType::String: {
                QString s;
                for (int i = 0; i < b.size(); ++i) {
                    s += QString::asprintf("%02x ", static_cast<unsigned char>(b[i]));
                }
                return s.trimmed();
            }
        }
        return {};
    };

    int row = table_->rowCount();
    table_->insertRow(row);
    table_->setItem(row, 0, new QTableWidgetItem(QString::number(++changeCount_)));
    table_->setItem(row, 1, new QTableWidgetItem(formatVal(lastBytes_)));
    table_->setItem(row, 2, new QTableWidgetItem(formatVal(current)));

    lastBytes_ = current;
}


#pragma once

#include <QDialog>
#include <cstdint>

class QTableWidget;
class QLabel;
class QTimer;

namespace core {
class TargetProcess;
enum class ValueType;
}

class ValueMonitorDialog : public QDialog {
    Q_OBJECT
public:
    ValueMonitorDialog(core::TargetProcess *proc,
                       uintptr_t address,
                       core::ValueType type,
                       QWidget *parent = nullptr);

private slots:
    void poll();

private:
    core::TargetProcess *proc_{};
    uintptr_t address_{0};
    core::ValueType type_;
    QTableWidget *table_{};
    QLabel *header_{};
    QTimer *timer_{};
    QByteArray lastBytes_;
    int changeCount_{0};

    QByteArray readCurrent() const;
};


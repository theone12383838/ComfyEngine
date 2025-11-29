#pragma once

#include <QDialog>
#include <vector>

#include "core/ProcessEnumerator.h"

class QListView;
class QPushButton;
class QLineEdit;
class QLabel;

class ProcessDialog : public QDialog {
    Q_OBJECT
public:
    explicit ProcessDialog(QWidget *parent = nullptr);

signals:
    void processChosen(pid_t pid, QString name);

private slots:
    void onOpen();
    void onRefresh();
    void onFilterChanged(const QString &text);

private:
    QListView *view_{};
    QPushButton *openBtn_{};
    QPushButton *refreshBtn_{};
    QLineEdit *filterEdit_{};
    QLabel *hintLabel_{};
    std::vector<core::ProcessInfo> allProcesses_;
    std::vector<core::ProcessInfo> processes_;

    void reload();
    void applyFilter(const QString &text);
};

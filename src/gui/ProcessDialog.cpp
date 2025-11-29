#include "gui/ProcessDialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QListView>
#include <QStringListModel>
#include <QLabel>
#include <QLineEdit>

#include <fstream>

ProcessDialog::ProcessDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("Select Process");
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel("Processes", this));

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText("Filter by name or PID...");
    layout->addWidget(filterEdit_);

    view_ = new QListView(this);
    view_->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(view_);

    auto *btnRow = new QHBoxLayout;
    refreshBtn_ = new QPushButton("Refresh", this);
    openBtn_ = new QPushButton("Open", this);
    auto *cancelBtn = new QPushButton("Cancel", this);
    btnRow->addWidget(refreshBtn_);
    btnRow->addStretch();
    btnRow->addWidget(openBtn_);
    btnRow->addWidget(cancelBtn);
    layout->addLayout(btnRow);

    hintLabel_ = new QLabel(this);
    hintLabel_->setWordWrap(true);
    layout->addWidget(hintLabel_);

    connect(openBtn_, &QPushButton::clicked, this, &ProcessDialog::onOpen);
    connect(refreshBtn_, &QPushButton::clicked, this, &ProcessDialog::onRefresh);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    connect(view_, &QListView::doubleClicked, this, &ProcessDialog::onOpen);
    connect(filterEdit_, &QLineEdit::textChanged, this, &ProcessDialog::onFilterChanged);

    reload();
}

void ProcessDialog::reload() {
    allProcesses_ = core::ProcessEnumerator::list();
    applyFilter(filterEdit_ ? filterEdit_->text() : QString());
    // best-effort ptrace hint
    int scope = -1;
    std::ifstream f("/proc/sys/kernel/yama/ptrace_scope");
    if (f.good()) f >> scope;
    if (scope > 0) {
        hintLabel_->setText(QString("ptrace_scope=%1; attach may fail unless running as root or after: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope").arg(scope));
    } else {
        hintLabel_->setText("");
    }
}

void ProcessDialog::applyFilter(const QString &text) {
    processes_.clear();
    QStringList entries;
    QString needle = text.trimmed();
    bool hasFilter = !needle.isEmpty();
    for (const auto &p : allProcesses_) {
        QString name = QString::fromStdString(p.name);
        QString pidStr = QString::number(p.pid);
        if (hasFilter) {
            if (!name.contains(needle, Qt::CaseInsensitive) &&
                !pidStr.contains(needle, Qt::CaseInsensitive)) {
                continue;
            }
        }
        processes_.push_back(p);
        entries.append(QString("%1 - %2").arg(pidStr, name));
    }
    auto *model = new QStringListModel(entries, view_);
    view_->setModel(model);
}

void ProcessDialog::onRefresh() {
    reload();
}

void ProcessDialog::onFilterChanged(const QString &text) {
    applyFilter(text);
}

void ProcessDialog::onOpen() {
    auto idx = view_->currentIndex();
    if (!idx.isValid()) return;
    int row = idx.row();
    if (row < 0 || row >= static_cast<int>(processes_.size())) return;
    const auto &p = processes_[row];
    emit processChosen(p.pid, QString::fromStdString(p.name));
    accept();
}

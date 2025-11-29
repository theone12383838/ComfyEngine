#include "gui/WatchWindow.h"

#include "core/DebugWatch.h"
#include "gui/MemoryViewerWindow.h"
#include "gui/MainWindow.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QPushButton>
#include <QTimer>

WatchWindow::WatchWindow(core::DebugWatchSession *session, QWidget *parent)
    : QDialog(parent), session_(session) {
    setWindowTitle("Instruction Monitor");
    auto *layout = new QVBoxLayout(this);

    table_ = new QTableWidget(this);
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({"Count", "Address", "Bytes", "Opcode", "Access"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table_);

    auto *btnRow = new QHBoxLayout;
    stopBtn_ = new QPushButton("Stop", this);
    btnRow->addWidget(stopBtn_);
    btnRow->addStretch();
    layout->addLayout(btnRow);

    timer_ = new QTimer(this);
    timer_->setInterval(200);
    connect(timer_, &QTimer::timeout, this, &WatchWindow::refresh);
    connect(stopBtn_, &QPushButton::clicked, this, &WatchWindow::onStop);
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (!session_ || !session_->isRunning()) return;
        if (row < 0 || row >= table_->rowCount()) return;
        bool ok = false;
        auto *addrItem = table_->item(row, 1);
        if (!addrItem) return;
        uintptr_t addr = addrItem->text().toULongLong(&ok, 0);
        if (!ok) return;
        if (!viewer_) {
            viewer_ = new MemoryViewerWindow();
            viewer_->setAttribute(Qt::WA_DeleteOnClose);
            connect(viewer_, &QObject::destroyed, this, [this]() { viewer_ = nullptr; });
        }
        viewer_->setTarget(&session_->proc(), addr);
        viewer_->show();
        viewer_->raise();
        viewer_->activateWindow();
        if (auto *main = MainWindow::instance()) {
            main->updateGlobalAddress(addr, core::ValueType::Int64, QStringLiteral("Watcher"));
        }
    });

    if (session_) {
        session_->start();
        timer_->start();
    }
}

WatchWindow::~WatchWindow() {
    if (session_) {
        session_->stop();
        delete session_;
        session_ = nullptr;
    }
}

void WatchWindow::refresh() {
    if (!session_ || !session_->isRunning()) {
        timer_->stop();
        return;
    }
    auto hits = session_->snapshot();
    table_->setRowCount(static_cast<int>(hits.size()));
    int row = 0;
    for (const auto &kv : hits) {
        auto addr = kv.first;
        const auto &hit = kv.second;
        auto ensureItem = [&](int c) -> QTableWidgetItem* {
            auto *item = table_->item(row, c);
            if (!item) {
                item = new QTableWidgetItem();
                table_->setItem(row, c, item);
            }
            return item;
        };
        ensureItem(0)->setText(QString::number(static_cast<qulonglong>(hit.count)));
        ensureItem(1)->setText(QString::asprintf("0x%016llx", static_cast<unsigned long long>(addr)));
        ensureItem(2)->setText(QString::fromStdString(hit.bytes));
        ensureItem(3)->setText(QString::fromStdString(hit.opcode));
        QString access = (hit.type == core::WatchType::Writes) ? "write" : "access";
        ensureItem(4)->setText(access);
        ++row;
    }
}

void WatchWindow::onStop() {
    if (session_) {
        session_->stop();
    }
    timer_->stop();
    close();
}

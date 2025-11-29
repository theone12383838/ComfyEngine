#pragma once

#include <QDialog>
#include <memory>

class QTableWidget;
class QPushButton;
class QTimer;

namespace core {
class DebugWatchSession;
}

class MemoryViewerWindow;

class WatchWindow : public QDialog {
    Q_OBJECT
public:
    explicit WatchWindow(core::DebugWatchSession *session, QWidget *parent = nullptr);
    ~WatchWindow();

private slots:
    void refresh();
    void onStop();

private:
    core::DebugWatchSession *session_;
    QTableWidget *table_{};
    QPushButton *stopBtn_{};
    QTimer *timer_{};
    MemoryViewerWindow *viewer_{};
};

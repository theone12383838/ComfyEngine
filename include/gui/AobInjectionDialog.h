#pragma once

#include <QDialog>
#include <memory>
#include <vector>

class QLineEdit;
class QPushButton;
class QTableWidget;
class QLabel;
class QCheckBox;
class QThread;

namespace core {
class TargetProcess;
class CodeInjector;
class MemoryScanner;
} // namespace core

class AobInjectionDialog : public QDialog {
    Q_OBJECT
public:
    AobInjectionDialog(core::TargetProcess *target,
                       core::CodeInjector *injector,
                       QWidget *parent = nullptr);
    ~AobInjectionDialog();
    void setStartAddress(uintptr_t address);

private:
    void setupUi();
    void startScan();
    void finishScan(bool ok);
    void applyPatch();
    void restorePatch();
    bool parsePattern(std::vector<int> &pattern) const;
    bool parseReplacement(std::vector<int> &replacement) const;
    void showStatus(const QString &message, bool error = false);

    core::TargetProcess *target_{nullptr};
    core::CodeInjector *injector_{nullptr};
    std::unique_ptr<core::MemoryScanner> scanner_;

    QLineEdit *patternEdit_{};
    QLineEdit *replacementEdit_{};
    QLineEdit *startEdit_{};
    QLineEdit *endEdit_{};
    QCheckBox *writableCheck_{};
    QCheckBox *executableCheck_{};
    QPushButton *scanBtn_{};
    QPushButton *applyBtn_{};
    QPushButton *restoreBtn_{};
    QTableWidget *resultsTable_{};
    QLabel *statusLabel_{};

    QThread *scanThread_{nullptr};
    bool busy_{false};
};

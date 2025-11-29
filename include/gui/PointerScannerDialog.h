#pragma once

#include <QDialog>
#include <memory>
#include <vector>
#include <cstdint>

class QLineEdit;
class QPushButton;
class QTableWidget;
class QCheckBox;

namespace core {
class TargetProcess;

struct PointerHit {
    uintptr_t baseAddress;
    int64_t offset;
    uintptr_t finalAddress;
};

class PointerScanner {
public:
    explicit PointerScanner(const TargetProcess &proc);

    std::vector<PointerHit> scan(uintptr_t target, int64_t maxOffset, bool writableOnly);

private:
    const TargetProcess &proc_;
};

} // namespace core

class PointerScannerDialog : public QDialog {
    Q_OBJECT
public:
    PointerScannerDialog(core::TargetProcess *proc, QWidget *parent = nullptr);

    void setTargetAddress(uintptr_t addr);

signals:
    void pointerSelected(uintptr_t base, qint64 offset, uintptr_t finalAddr);
    void pointerPreview(const std::vector<core::PointerHit> &hits, int selectedIndex);

private slots:
    void onStartScan();

private:
    core::TargetProcess *proc_{};
    QLineEdit *targetEdit_{};
    QLineEdit *maxOffsetEdit_{};
    QCheckBox *writableOnlyCheck_{};
    QPushButton *startBtn_{};
    QTableWidget *resultsTable_{};
    std::vector<core::PointerHit> hits_;
};

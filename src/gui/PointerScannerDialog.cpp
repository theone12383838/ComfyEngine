#include "gui/PointerScannerDialog.h"

#include "core/TargetProcess.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QCheckBox>

namespace core {

PointerScanner::PointerScanner(const TargetProcess &proc) : proc_(proc) {}

std::vector<PointerHit> PointerScanner::scan(uintptr_t target, int64_t maxOffset, bool writableOnly) {
    std::vector<PointerHit> hits;
    if (maxOffset <= 0) return hits;
    constexpr size_t kChunk = 64 * 1024;
    std::vector<uint8_t> buffer(kChunk);
    for (const auto &region : proc_.regions()) {
        if (region.perms.find('r') == std::string::npos) continue;
        if (writableOnly && region.perms.find('w') == std::string::npos) continue;
        uintptr_t start = region.start;
        uintptr_t end = region.end;
        for (uintptr_t addr = start; addr + sizeof(uintptr_t) <= end; addr += kChunk) {
            size_t toRead = std::min(kChunk, end - addr);
            buffer.resize(toRead);
            if (!proc_.readMemory(addr, buffer.data(), toRead)) continue;
            for (size_t offset = 0; offset + sizeof(uintptr_t) <= toRead; offset += sizeof(uintptr_t)) {
                uintptr_t val = 0;
                std::memcpy(&val, buffer.data() + offset, sizeof(uintptr_t));
                if (val == 0) continue;
                int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(val);
                if (diff >= -maxOffset && diff <= maxOffset) {
                    PointerHit hit;
                    hit.baseAddress = addr + offset;
                    hit.offset = diff;
                    hit.finalAddress = val + diff;
                    hits.push_back(hit);
                }
            }
        }
    }
    return hits;
}

} // namespace core

PointerScannerDialog::PointerScannerDialog(core::TargetProcess *proc, QWidget *parent)
    : QDialog(parent), proc_(proc) {
    setWindowTitle("Pointer Scanner");
    auto *mainLayout = new QVBoxLayout(this);

    auto *topRow = new QHBoxLayout;
    topRow->addWidget(new QLabel("Target address", this));
    targetEdit_ = new QLineEdit(this);
    topRow->addWidget(targetEdit_);
    topRow->addWidget(new QLabel("Max offset", this));
    maxOffsetEdit_ = new QLineEdit(this);
    maxOffsetEdit_->setText("4096");
    topRow->addWidget(maxOffsetEdit_);
    writableOnlyCheck_ = new QCheckBox("Writable only", this);
    topRow->addWidget(writableOnlyCheck_);
    startBtn_ = new QPushButton("Start scan", this);
    topRow->addWidget(startBtn_);
    mainLayout->addLayout(topRow);

    resultsTable_ = new QTableWidget(this);
    resultsTable_->setColumnCount(3);
    resultsTable_->setHorizontalHeaderLabels({"Base", "Offset", "Final"});
    resultsTable_->horizontalHeader()->setStretchLastSection(true);
    mainLayout->addWidget(resultsTable_);

    connect(startBtn_, &QPushButton::clicked, this, &PointerScannerDialog::onStartScan);
    auto emitPreview = [this](int row) {
        if (row < 0 || row >= static_cast<int>(hits_.size())) return;
        emit pointerPreview(hits_, row);
    };
    connect(resultsTable_, &QTableWidget::cellClicked, this, [emitPreview](int row, int) { emitPreview(row); });
    connect(resultsTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (row < 0 || row >= static_cast<int>(hits_.size())) return;
        const auto &h = hits_[row];
        emit pointerSelected(h.baseAddress, h.offset, h.finalAddress);
    });
}

void PointerScannerDialog::setTargetAddress(uintptr_t addr) {
    targetEdit_->setText(QString::asprintf("0x%llx", static_cast<unsigned long long>(addr)));
}

void PointerScannerDialog::onStartScan() {
    if (!proc_) return;
    bool okAddr = false;
    bool okOff = false;
    uintptr_t target = targetEdit_->text().toULongLong(&okAddr, 0);
    qint64 maxOffset = maxOffsetEdit_->text().toLongLong(&okOff, 10);
    if (!okAddr || !okOff || maxOffset <= 0) {
        return;
    }
    core::PointerScanner scanner(*proc_);
    hits_ = scanner.scan(target, maxOffset, writableOnlyCheck_->isChecked());
    resultsTable_->setRowCount(static_cast<int>(hits_.size()));
    for (int i = 0; i < static_cast<int>(hits_.size()); ++i) {
        const auto &h = hits_[i];
        auto *baseItem = new QTableWidgetItem(QString::asprintf("0x%llx",
            static_cast<unsigned long long>(h.baseAddress)));
        auto *offItem = new QTableWidgetItem(QString::number(h.offset));
        auto *finalItem = new QTableWidgetItem(QString::asprintf("0x%llx",
            static_cast<unsigned long long>(h.finalAddress)));
        resultsTable_->setItem(i, 0, baseItem);
        resultsTable_->setItem(i, 1, offItem);
        resultsTable_->setItem(i, 2, finalItem);
    }
    if (!hits_.empty()) {
        resultsTable_->selectRow(0);
        emit pointerPreview(hits_, 0);
    }
}

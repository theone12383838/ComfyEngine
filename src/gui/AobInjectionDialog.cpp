#include "gui/AobInjectionDialog.h"

#include "core/CodeInjector.h"
#include "core/MemoryScanner.h"
#include "core/TargetProcess.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QCheckBox>
#include <QThread>
#include <QSet>

AobInjectionDialog::AobInjectionDialog(core::TargetProcess *target,
                                       core::CodeInjector *injector,
                                       QWidget *parent)
    : QDialog(parent), target_(target), injector_(injector) {
    setWindowTitle("AoB Injection");
    setModal(false);
    if (target_) {
        scanner_ = std::make_unique<core::MemoryScanner>(*target_);
    }
    setupUi();
}

void AobInjectionDialog::setStartAddress(uintptr_t address) {
    if (!startEdit_) return;
    startEdit_->setText(QString::asprintf("0x%llx", static_cast<unsigned long long>(address)));
}

AobInjectionDialog::~AobInjectionDialog() {
    if (scanThread_) {
        scanThread_->requestInterruption();
        scanThread_->quit();
        scanThread_->wait(100);
        delete scanThread_;
    }
}

void AobInjectionDialog::setupUi() {
    auto *layout = new QVBoxLayout(this);

    auto *form = new QFormLayout;
    patternEdit_ = new QLineEdit(this);
    patternEdit_->setPlaceholderText("e.g. 90 90 ?? FF");
    replacementEdit_ = new QLineEdit(this);
    replacementEdit_->setPlaceholderText("Replacement bytes (same length, hex)");
    startEdit_ = new QLineEdit(this);
    startEdit_->setPlaceholderText("0x0");
    endEdit_ = new QLineEdit(this);
    endEdit_->setPlaceholderText("0x0");
    writableCheck_ = new QCheckBox("Writable regions", this);
    executableCheck_ = new QCheckBox("Executable regions", this);

    form->addRow("Pattern:", patternEdit_);
    form->addRow("Replacement:", replacementEdit_);
    form->addRow("Start address:", startEdit_);
    form->addRow("End address:", endEdit_);
    form->addRow("", writableCheck_);
    form->addRow("", executableCheck_);
    layout->addLayout(form);

    auto *btnRow = new QHBoxLayout;
    scanBtn_ = new QPushButton("Scan", this);
    applyBtn_ = new QPushButton("Apply Patch", this);
    restoreBtn_ = new QPushButton("Restore", this);
    btnRow->addWidget(scanBtn_);
    btnRow->addStretch();
    btnRow->addWidget(applyBtn_);
    btnRow->addWidget(restoreBtn_);
    layout->addLayout(btnRow);

    resultsTable_ = new QTableWidget(this);
    resultsTable_->setColumnCount(2);
    resultsTable_->setHorizontalHeaderLabels({"Address", "Bytes"});
    resultsTable_->horizontalHeader()->setStretchLastSection(true);
    resultsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    layout->addWidget(resultsTable_);

    statusLabel_ = new QLabel(this);
    layout->addWidget(statusLabel_);

    connect(scanBtn_, &QPushButton::clicked, this, &AobInjectionDialog::startScan);
    connect(applyBtn_, &QPushButton::clicked, this, &AobInjectionDialog::applyPatch);
    connect(restoreBtn_, &QPushButton::clicked, this, &AobInjectionDialog::restorePatch);
}

bool AobInjectionDialog::parsePattern(std::vector<int> &pattern) const {
    const QString text = patternEdit_->text().trimmed();
    if (text.isEmpty()) return false;
    return core::MemoryScanner::parseAobPattern(text.toStdString(), pattern);
}

bool AobInjectionDialog::parseReplacement(std::vector<int> &replacement) const {
    const QString text = replacementEdit_->text().trimmed();
    if (text.isEmpty()) return false;
    if (!core::MemoryScanner::parseAobPattern(text.toStdString(), replacement)) return false;
    for (int v : replacement) {
        if (v < 0) return false; // no wildcards allowed in replacement
    }
    return true;
}

void AobInjectionDialog::startScan() {
    if (!target_ || !target_->isAttached() || !scanner_) {
        showStatus("No target attached.", true);
        return;
    }
    if (busy_) return;

    std::vector<int> pattern;
    if (!parsePattern(pattern)) {
        showStatus("Invalid pattern.", true);
        return;
    }

    core::ScanParams params;
    params.type = core::ValueType::ArrayOfByte;
    params.mode = core::ScanMode::Aob;
    params.value1 = patternEdit_->text().trimmed().toStdString();
    bool okStart = false;
    bool okEnd = false;
    params.startAddress = startEdit_->text().trimmed().isEmpty()
        ? 0
        : startEdit_->text().trimmed().toULongLong(&okStart, 0);
    params.endAddress = endEdit_->text().trimmed().isEmpty()
        ? 0
        : endEdit_->text().trimmed().toULongLong(&okEnd, 0);
    if (!okStart && !startEdit_->text().trimmed().isEmpty()) {
        showStatus("Invalid start address.", true);
        return;
    }
    if (!okEnd && !endEdit_->text().trimmed().isEmpty()) {
        showStatus("Invalid end address.", true);
        return;
    }
    params.requireWritable = writableCheck_->isChecked();
    params.requireExecutable = executableCheck_->isChecked();

    scanner_->resetCancel();
    scanner_->reset();
    busy_ = true;
    scanBtn_->setEnabled(false);
    applyBtn_->setEnabled(false);
    restoreBtn_->setEnabled(false);
    resultsTable_->setRowCount(0);
    showStatus("Scanning...");

    core::MemoryScanner *scanner = scanner_.get();
    auto threadFunc = [this, scanner, params]() {
        bool ok = scanner->firstScan(params);
        QMetaObject::invokeMethod(this, [this, ok]() { finishScan(ok); }, Qt::QueuedConnection);
    };
    scanThread_ = QThread::create(threadFunc);
    connect(scanThread_, &QThread::finished, scanThread_, &QObject::deleteLater);
    connect(scanThread_, &QThread::finished, this, [this]() { scanThread_ = nullptr; });
    scanThread_->start();
}

void AobInjectionDialog::finishScan(bool ok) {
    busy_ = false;
    scanBtn_->setEnabled(true);
    applyBtn_->setEnabled(true);
    restoreBtn_->setEnabled(true);
    if (!ok) {
        showStatus("Scan failed or cancelled.", true);
        return;
    }
    const auto &res = scanner_->results();
    resultsTable_->setRowCount(static_cast<int>(res.size()));
    std::vector<int> pattern;
    parsePattern(pattern);
    size_t bytesToShow = pattern.size();
    if (bytesToShow == 0) bytesToShow = 16;

    std::vector<uint8_t> buffer(bytesToShow);
    for (int row = 0; row < static_cast<int>(res.size()); ++row) {
        uintptr_t addr = res[row].address;
        QString addrStr = QString::asprintf("0x%016llx", static_cast<unsigned long long>(addr));
        auto *addrItem = new QTableWidgetItem(addrStr);
        addrItem->setData(Qt::UserRole, QVariant::fromValue(static_cast<qulonglong>(addr)));
        resultsTable_->setItem(row, 0, addrItem);

        QString bytesStr = "(unreadable)";
        if (target_ && target_->readMemory(addr, buffer.data(), buffer.size())) {
            bytesStr.clear();
            for (size_t i = 0; i < buffer.size(); ++i) {
                bytesStr += QString::asprintf("%02X ", buffer[i]);
            }
            if (!bytesStr.isEmpty()) bytesStr.chop(1);
        }
        resultsTable_->setItem(row, 1, new QTableWidgetItem(bytesStr));
    }
    showStatus(QString("Found %1 matches.").arg(res.size()));
}

void AobInjectionDialog::applyPatch() {
    if (!target_ || !injector_) {
        showStatus("No target attached.", true);
        return;
    }
    auto selected = resultsTable_->selectedItems();
    if (selected.isEmpty()) {
        showStatus("Select at least one match.", true);
        return;
    }
    std::vector<int> pattern;
    if (!parsePattern(pattern)) {
        showStatus("Invalid pattern.", true);
        return;
    }
    std::vector<int> replacement;
    if (!parseReplacement(replacement)) {
        showStatus("Invalid replacement bytes.", true);
        return;
    }
    if (replacement.size() != pattern.size()) {
        showStatus("Replacement length must match pattern.", true);
        return;
    }

    std::vector<uint8_t> patchBytes(replacement.size());
    for (size_t i = 0; i < replacement.size(); ++i) {
        patchBytes[i] = static_cast<uint8_t>(replacement[i] & 0xFF);
    }

    QSet<int> rows;
    for (auto *item : selected) rows.insert(item->row());

    size_t patched = 0;
    std::vector<uint8_t> current(pattern.size());
    for (int row : rows) {
        auto *addrItem = resultsTable_->item(row, 0);
        if (!addrItem) continue;
        uintptr_t addr = static_cast<uintptr_t>(addrItem->data(Qt::UserRole).toULongLong());
        if (!target_->readMemory(addr, current.data(), current.size())) {
            showStatus(QString("Failed to read address 0x%1").arg(addr, 0, 16), true);
            continue;
        }
        bool match = true;
        for (size_t i = 0; i < pattern.size(); ++i) {
            int p = pattern[i];
            if (p == -1) continue;
            if (current[i] != static_cast<uint8_t>(p & 0xFF)) {
                match = false;
                break;
            }
        }
        if (!match) {
            showStatus(QString("Pattern mismatch at 0x%1, skipped").arg(addr, 0, 16), true);
            continue;
        }
        if (!injector_->patchBytes(addr, patchBytes)) {
            showStatus(QString("Failed to patch 0x%1").arg(addr, 0, 16), true);
            continue;
        }
        patched++;
    }

    if (patched > 0) {
        showStatus(QString("Applied patch to %1 location(s).").arg(patched));
    }
}

void AobInjectionDialog::restorePatch() {
    if (!injector_) {
        showStatus("No injector available.", true);
        return;
    }
    auto selected = resultsTable_->selectedItems();
    if (selected.isEmpty()) {
        showStatus("Select at least one match.", true);
        return;
    }
    QSet<int> rows;
    for (auto *item : selected) rows.insert(item->row());

    size_t restored = 0;
    for (int row : rows) {
        auto *addrItem = resultsTable_->item(row, 0);
        if (!addrItem) continue;
        uintptr_t addr = static_cast<uintptr_t>(addrItem->data(Qt::UserRole).toULongLong());
        if (injector_->restore(addr)) {
            restored++;
        }
    }
    if (restored > 0) {
        showStatus(QString("Restored %1 patch(es).").arg(restored));
    } else {
        showStatus("Nothing restored.", true);
    }
}

void AobInjectionDialog::showStatus(const QString &message, bool error) {
    statusLabel_->setText(message);
    QPalette pal = statusLabel_->palette();
    pal.setColor(QPalette::WindowText, error ? Qt::red : Qt::green);
    statusLabel_->setPalette(pal);
}

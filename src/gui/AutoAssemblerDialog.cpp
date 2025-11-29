#include "gui/AutoAssemblerDialog.h"

#include "core/CodeInjector.h"
#include "core/TargetProcess.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QTextEdit>
#include <QLineEdit>
#include <QSpinBox>
#include <QGroupBox>
#include <QGridLayout>
#include <QStringList>
#include <QToolButton>
#include <QMenu>

#include <sstream>
#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace {
std::string trim_copy(const std::string &s) {
    std::string out = s;
    out.erase(out.begin(), std::find_if(out.begin(), out.end(), [](unsigned char c) { return !std::isspace(c); }));
    out.erase(std::find_if(out.rbegin(), out.rend(), [](unsigned char c) { return !std::isspace(c); }).base(), out.end());
    return out;
}
} // namespace

AutoAssemblerDialog::AutoAssemblerDialog(core::CodeInjector *injector, QWidget *parent)
    : QDialog(parent), injector_(injector) {
    setWindowTitle("Auto Assembler");
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel("Syntax: 'patch <addr> <hex bytes...>' or 'restore <addr>'.\nUse [ENABLE]/[DISABLE] sections.", this));

    auto *templateBox = new QGroupBox("Code Injection Template", this);
    auto *templateLayout = new QGridLayout;
    templateAddressEdit_ = new QLineEdit(this);
    templateAddressEdit_->setPlaceholderText("0x0");
    templateSizeSpin_ = new QSpinBox(this);
    templateSizeSpin_->setRange(5, 32);
    templateSizeSpin_->setValue(5);
    templateHint_ = new QLabel("Use templates for ComfyEngine-style code/AoB injections.", this);
    templateButton_ = new QToolButton(this);
    templateButton_->setText("Templates");
    templateButton_->setPopupMode(QToolButton::MenuButtonPopup);
    templateMenu_ = new QMenu(templateButton_);
    auto codeAct = templateMenu_->addAction("Code Injection");
    codeAct->setData(static_cast<int>(TemplateKind::CodeInjection));
    auto aobAct = templateMenu_->addAction("AoB Injection");
    aobAct->setData(static_cast<int>(TemplateKind::AobInjection));
    auto emptyAct = templateMenu_->addAction("Empty Script");
    emptyAct->setData(static_cast<int>(TemplateKind::Empty));
    templateButton_->setMenu(templateMenu_);
    templateLayout->addWidget(new QLabel("Address", this), 0, 0);
    templateLayout->addWidget(templateAddressEdit_, 0, 1);
    templateLayout->addWidget(new QLabel("Bytes to replace", this), 1, 0);
    templateLayout->addWidget(templateSizeSpin_, 1, 1);
    templateLayout->addWidget(templateButton_, 2, 0, 1, 2);
    templateLayout->addWidget(templateHint_, 3, 0, 1, 2);
    templateBox->setLayout(templateLayout);
    layout->addWidget(templateBox);

    auto *scriptRow = new QHBoxLayout;
    scriptNameEdit_ = new QLineEdit(this);
    scriptNameEdit_->setPlaceholderText("Script description");
    addToTableBtn_ = new QPushButton("Add to Cheat Table", this);
    scriptRow->addWidget(scriptNameEdit_);
    scriptRow->addWidget(addToTableBtn_);
    layout->addLayout(scriptRow);

    editor_ = new QPlainTextEdit(this);
    editor_->setPlaceholderText("patch 0x401000 90 90 90\nrestore 0x401000");
    layout->addWidget(editor_);

    auto *btnRow = new QHBoxLayout;
    enableBtn_ = new QPushButton("Enable", this);
    disableBtn_ = new QPushButton("Disable", this);
    btnRow->addWidget(enableBtn_);
    btnRow->addWidget(disableBtn_);
    btnRow->addStretch();
    layout->addLayout(btnRow);

    statusLabel_ = new QLabel("Idle", this);
    layout->addWidget(statusLabel_);

    log_ = new QTextEdit(this);
    log_->setReadOnly(true);
    log_->setFixedHeight(120);
    layout->addWidget(log_);

    connect(enableBtn_, &QPushButton::clicked, this, &AutoAssemblerDialog::onEnable);
    connect(disableBtn_, &QPushButton::clicked, this, &AutoAssemblerDialog::onDisable);
    connect(templateButton_, &QToolButton::clicked, this, &AutoAssemblerDialog::onGenerateTemplate);
    connect(templateMenu_, &QMenu::triggered, this, [this](QAction *act) {
        insertTemplate(static_cast<TemplateKind>(act->data().toInt()));
    });
    connect(addToTableBtn_, &QPushButton::clicked, this, &AutoAssemblerDialog::onAddToTable);
}

std::optional<AutoAssemblerDialog::Command> AutoAssemblerDialog::parseLine(const std::string &line, QString &errorOut,
                                                                          const std::unordered_map<std::string, uintptr_t> &symbols) const {
    if (line.empty()) return std::nullopt;
    if (line[0] == ';' || line[0] == '#') return std::nullopt;
    if (line.size() >= 2 && line[0] == '/' && line[1] == '/') return std::nullopt;
    std::istringstream ls(line);
    std::string word;
    if (!(ls >> word)) return std::nullopt;
    Command cmd;
    if (word == "patch") {
        cmd.type = Command::Type::Patch;
    } else if (word == "restore") {
        cmd.type = Command::Type::Restore;
    } else {
        errorOut = QString("Unknown directive: %1").arg(QString::fromStdString(word));
        return std::nullopt;
    }
    std::string addrStr;
    if (!(ls >> addrStr)) {
        errorOut = "Missing address";
        return std::nullopt;
    }
    uintptr_t addr = 0;
    if (!parseAddressWithSymbols(addrStr, symbols, addr, errorOut)) {
        return std::nullopt;
    }
    cmd.address = addr;
    if (cmd.type == Command::Type::Patch) {
        std::string tok;
        while (ls >> tok) {
            try {
                uint8_t b = static_cast<uint8_t>(std::stoul(tok, nullptr, 16));
                cmd.bytes.push_back(b);
            } catch (...) {
                errorOut = QString("Invalid byte: %1").arg(QString::fromStdString(tok));
                return std::nullopt;
            }
        }
        if (cmd.bytes.empty()) {
            errorOut = "No bytes provided";
            return std::nullopt;
        }
    }
    return cmd;
}

std::pair<AutoAssemblerDialog::CommandList, AutoAssemblerDialog::CommandList> AutoAssemblerDialog::parseSections(const QString &scriptText, QStringList &errors) {
    symbols_.clear();
    // preload module bases so users can write module+offset
    auto modules = collectModuleBases();
    symbols_.insert(modules.begin(), modules.end());
    CommandList enable, disable;
    bool inEnable = true;
    const auto text = scriptText.toStdString();
    std::istringstream iss(text);
    std::string line;
    int lineNo = 0;
    while (std::getline(iss, line)) {
        lineNo++;
        if (line.empty()) continue;
        std::string trimmed = trim_copy(line);
        if (trimmed.empty()) continue;
        if (trimmed == "[ENABLE]" || trimmed == "[enable]") {
            inEnable = true;
            continue;
        }
        if (trimmed == "[DISABLE]" || trimmed == "[disable]") {
            inEnable = false;
            continue;
        }
        // aobscan directive
        if (trimmed.rfind("aobscan", 0) == 0) {
            std::string name;
            std::string module;
            std::string pattern;
            bool moduleVariant = trimmed.rfind("aobscanmodule", 0) == 0;
            auto joinFrom = [](const std::vector<std::string> &parts, size_t start) {
                std::string out;
                for (size_t i = start; i < parts.size(); ++i) {
                    if (!out.empty()) out.push_back(',');
                    out += parts[i];
                }
                return trim_copy(out);
            };
            auto assignArgs = [&](const std::vector<std::string> &parts) {
                if (moduleVariant) {
                    if (parts.size() < 3) return false;
                    name = parts[0];
                    module = parts[1];
                    pattern = joinFrom(parts, 2);
                } else {
                    if (parts.size() < 2) return false;
                    name = parts[0];
                    pattern = joinFrom(parts, 1);
                }
                return true;
            };
            bool parsed = false;
            auto parenPos = trimmed.find('(');
            if (parenPos != std::string::npos) {
                auto endParen = trimmed.find(')', parenPos);
                auto inside = trimmed.substr(parenPos + 1,
                                             endParen == std::string::npos ? std::string::npos : endParen - parenPos - 1);
                std::vector<std::string> parts;
                std::stringstream argStream(inside);
                std::string chunk;
                while (std::getline(argStream, chunk, ',')) {
                    parts.push_back(trim_copy(chunk));
                }
                parsed = assignArgs(parts);
            }
            if (!parsed) {
                std::istringstream ls(trimmed);
                std::string kw;
                ls >> kw;
                ls >> name;
                if (moduleVariant) ls >> module;
                std::string tok;
                while (ls >> tok) {
                    if (!pattern.empty()) pattern.push_back(' ');
                    pattern += tok;
                }
                parsed = !name.empty() && !pattern.empty() && (!moduleVariant || !module.empty());
            }
            pattern = trim_copy(pattern);
            if (moduleVariant) module = trim_copy(module);
            if (moduleVariant) {
                if (module.size() >= 2 && (module.front() == '"' || module.front() == '\'') && module.back() == module.front()) {
                    module = module.substr(1, module.size() - 2);
                }
            }
            if (!parsed) {
                errors << QString("Line %1: invalid aobscan syntax").arg(lineNo);
                continue;
            }
            QString err;
            auto addrOpt = scanAob(pattern, err, moduleVariant ? module : std::string());
            if (!addrOpt.has_value()) {
                errors << QString("Line %1: aobscan failed for %2 (%3)")
                              .arg(lineNo)
                              .arg(QString::fromStdString(name))
                              .arg(err);
                continue;
            }
            symbols_[name] = *addrOpt;
            QString logTag = moduleVariant ? QStringLiteral("aobscanmodule") : QStringLiteral("aobscan");
            QString moduleInfo = moduleVariant ? QStringLiteral(" [%1]").arg(QString::fromStdString(module)) : QString();
            log_->append(QString("%1 %2%3 -> 0x%4")
                             .arg(logTag)
                             .arg(QString::fromStdString(name))
                             .arg(moduleInfo)
                             .arg(static_cast<unsigned long long>(*addrOpt), 0, 16));
            continue;
        }

        QString err;
        auto cmdOpt = parseLine(trimmed, err, symbols_);
        if (!cmdOpt) {
            if (!err.isEmpty()) {
                errors << QString("Line %1: %2").arg(lineNo).arg(err);
            }
            continue;
        }
        if (inEnable) enable.push_back(*cmdOpt);
        else disable.push_back(*cmdOpt);
    }
    if (enable.empty() && disable.empty()) {
        QString err;
        auto single = parseLine(text, err, symbols_);
        if (single) {
            enable.push_back(*single);
        } else if (!err.isEmpty()) {
            errors << err;
        }
    }
    return {enable, disable};
}

void AutoAssemblerDialog::applyCommands(const CommandList &cmds) {
    if (!injector_) return;
    for (const auto &cmd : cmds) {
        if (cmd.type != Command::Type::Patch) continue;
        injector_->patchBytes(cmd.address, cmd.bytes);
    }
}

void AutoAssemblerDialog::restoreCommands(const CommandList &cmds) {
    if (!injector_) return;
    for (const auto &cmd : cmds) {
        if (cmd.type == Command::Type::Restore) {
            injector_->restore(cmd.address);
        } else if (cmd.type == Command::Type::Patch) {
            injector_->restore(cmd.address);
        }
    }
}

void AutoAssemblerDialog::setStatus(const QString &text, bool ok) {
    statusLabel_->setText(text);
    statusLabel_->setStyleSheet(ok ? "color: green;" : "color: red;");
    if (!ok) {
        log_->append(text);
    }
}

bool AutoAssemblerDialog::parseAddressWithSymbols(const std::string &addrStr,
                                                  const std::unordered_map<std::string, uintptr_t> &symbols,
                                                  uintptr_t &outAddr, QString &errorOut) const {
    bool ok = false;
    outAddr = QString::fromStdString(addrStr).toULongLong(&ok, 0);
    if (ok && outAddr != 0) return true;
    // try symbol+offset
    size_t posPlus = addrStr.find('+');
    size_t posMinus = addrStr.find('-', 1);
    size_t pos = std::min(posPlus == std::string::npos ? addrStr.size() : posPlus,
                          posMinus == std::string::npos ? addrStr.size() : posMinus);
    std::string name = addrStr.substr(0, pos);
    auto it = symbols.find(name);
    if (it == symbols.end()) {
        errorOut = QString("Unknown symbol: %1").arg(QString::fromStdString(name));
        return false;
    }
    uintptr_t base = it->second;
    intptr_t offset = 0;
    if (pos < addrStr.size()) {
        std::string offStr = addrStr.substr(pos);
        char sign = offStr[0];
        offStr.erase(offStr.begin());
        bool offOk = false;
        qint64 offVal = QString::fromStdString(offStr).toLongLong(&offOk, 0);
        if (!offOk) {
            errorOut = "Invalid offset";
            return false;
        }
        offset = (sign == '-') ? -offVal : offVal;
    }
    outAddr = base + offset;
    return true;
}

std::optional<uintptr_t> AutoAssemblerDialog::scanAob(const std::string &pattern, QString &errorOut,
                                                      const std::string &moduleFilter) const {
    if (!injector_) {
        errorOut = "No injector";
        return std::nullopt;
    }
    const auto &proc = injector_->target();
    if (!proc.isAttached()) {
        errorOut = "Not attached";
        return std::nullopt;
    }
    auto normalize = [](std::string str) {
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); });
        return str;
    };
    std::string filter = trim_copy(moduleFilter);
    std::string loweredFilter = normalize(filter);
    bool filterAll = loweredFilter.empty() || loweredFilter == "$process" || loweredFilter == "$PROCESS";

    auto moduleMatches = [&](const core::MemoryRegion &region) {
        if (filterAll) return true;
        if (region.path.empty()) return false;
        std::string pathLower = normalize(region.path);
        if (pathLower == loweredFilter) return true;
        std::string base = region.path;
        auto slash = base.find_last_of("/\\");
        if (slash != std::string::npos) base = base.substr(slash + 1);
        return normalize(base) == loweredFilter;
    };

    // parse pattern
    std::vector<int> pat;
    {
        std::istringstream iss(pattern);
        std::string tok;
        while (iss >> tok) {
            if (tok == "??" || tok == "?" || tok == "**") {
                pat.push_back(-1);
            } else {
                try {
                    int v = std::stoi(tok, nullptr, 16);
                    pat.push_back(v & 0xFF);
                } catch (...) {
                    errorOut = QString("Bad pattern byte: %1").arg(QString::fromStdString(tok));
                    return std::nullopt;
                }
            }
        }
    }
    if (pat.empty()) {
        errorOut = "Empty pattern";
        return std::nullopt;
    }
    constexpr size_t kChunk = 64 * 1024;
    std::vector<unsigned char> buffer(kChunk + pat.size());
    for (const auto &region : proc.regions()) {
        if (region.perms.find('r') == std::string::npos) continue;
        if (!moduleMatches(region)) continue;
        auto start = region.start;
        auto end = region.end;
        for (uintptr_t addr = start; addr < end; addr += kChunk) {
            size_t toRead = std::min(kChunk, end - addr);
            buffer.resize(toRead + pat.size());
            if (!proc.readMemory(addr, buffer.data(), toRead)) continue;
            size_t limit = toRead >= pat.size() ? toRead - pat.size() + 1 : 0;
            for (size_t i = 0; i < limit; ++i) {
                bool match = true;
                for (size_t j = 0; j < pat.size(); ++j) {
                    int p = pat[j];
                    if (p == -1) continue;
                    if (buffer[i + j] != static_cast<unsigned char>(p)) { match = false; break; }
                }
                if (match) {
                    return addr + i;
                }
            }
        }
    }
    errorOut = "Pattern not found";
    return std::nullopt;
}

std::unordered_map<std::string, uintptr_t> AutoAssemblerDialog::collectModuleBases() const {
    std::unordered_map<std::string, uintptr_t> mods;
    if (!injector_) return mods;
    const auto &proc = injector_->target();
    if (!proc.isAttached()) return mods;
    for (const auto &r : proc.regions()) {
        if (r.path.empty()) continue;
        // simple basename
        auto pos = r.path.find_last_of('/');
        std::string name = (pos == std::string::npos) ? r.path : r.path.substr(pos + 1);
        if (mods.find(name) == mods.end()) {
            mods[name] = r.start;
        }
    }
    return mods;
}

void AutoAssemblerDialog::onEnable() {
    if (!injector_) {
        setStatus("No injector set", false);
        return;
    }
    QStringList errors;
    auto [enable, disable] = parseSections(buildScriptFromEditor(), errors);
    log_->clear();
    for (const auto &err : errors) {
        log_->append(err);
    }
    if (!errors.isEmpty()) {
        setStatus("Parse errors", false);
        return;
    }
    if (enable.empty() && disable.empty()) {
        setStatus("No commands found", false);
        return;
    }
    applyCommands(enable);
    lastEnable_ = enable;
    lastDisable_ = disable;
    enabled_ = true;
    setStatus("Enabled", true);
}

void AutoAssemblerDialog::onDisable() {
    if (!injector_) {
        setStatus("No injector set", false);
        return;
    }
    if (!enabled_) {
        setStatus("Script not enabled", false);
        return;
    }
    if (!lastDisable_.empty()) {
        applyCommands(lastDisable_);
    } else {
        restoreCommands(lastEnable_);
    }
    enabled_ = false;
    setStatus("Disabled", true);
}

bool AutoAssemblerDialog::executeScriptText(const QString &script, bool enable, QString *logOut) {
    if (!injector_) return false;
    QStringList errors;
    auto [enableCmds, disableCmds] = parseSections(script, errors);
    if (!errors.isEmpty()) {
        if (logOut) *logOut = errors.join('\n');
        return false;
    }
    if (enable) {
        applyCommands(enableCmds);
    } else {
        if (!disableCmds.empty()) {
            applyCommands(disableCmds);
        } else {
            restoreCommands(enableCmds);
        }
    }
    return true;
}
void AutoAssemblerDialog::setInjectionContext(uintptr_t address, const std::vector<uint8_t> &originalBytes) {
    templateAddress_ = address;
    templateBytes_ = originalBytes;
    if (address != 0) {
        templateAddressEdit_->setText(QString::asprintf("0x%llx", static_cast<unsigned long long>(address)));
        if (scriptNameEdit_ && scriptNameEdit_->text().isEmpty()) {
            scriptNameEdit_->setText(QString("Script %1").arg(QString::number(address, 16)));
        }
    }
    if (!templateBytes_.empty()) {
        templateSizeSpin_->setValue(static_cast<int>(templateBytes_.size()));
    }
}

void AutoAssemblerDialog::setScriptForEditing(const QString &name, const QString &script) {
    if (scriptNameEdit_) scriptNameEdit_->setText(name);
    if (editor_) editor_->setPlainText(script);
}

QString AutoAssemblerDialog::joinBytes(const std::vector<uint8_t> &bytes, const QString &sep) const {
    QStringList list;
    for (uint8_t b : bytes) {
        list << QString::asprintf("%02X", b);
    }
    return list.join(sep);
}

std::vector<uint8_t> AutoAssemblerDialog::ensureTemplateBytes(uintptr_t address, QString &errorOut) const {
    std::vector<uint8_t> bytes = templateBytes_;
    if (bytes.empty()) {
        int count = templateSizeSpin_ ? templateSizeSpin_->value() : 5;
        if (count < 5) count = 5;
        bytes.resize(static_cast<size_t>(count));
        if (!injector_ || !injector_->target().readMemory(address, bytes.data(), bytes.size())) {
            errorOut = "Failed to read bytes for template.";
            bytes.clear();
        }
    }
    return bytes;
}

void AutoAssemblerDialog::insertTemplate(TemplateKind kind) {
    uintptr_t address = templateAddress_;
    if (address == 0) {
        bool ok = false;
        address = templateAddressEdit_->text().trimmed().toULongLong(&ok, 0);
        if (!ok || address == 0) {
            setStatus("Invalid address for template.", false);
            return;
        }
    }

    QString error;
    auto bytes = ensureTemplateBytes(address, error);
    if (bytes.empty()) {
        setStatus(error.isEmpty() ? "Failed to prepare template bytes." : error, false);
        return;
    }

    QString script;
    QString addrStr = QString::asprintf("0x%llx", static_cast<unsigned long long>(address));
    QString bytesJoined = joinBytes(bytes, " ");

    switch (kind) {
        case TemplateKind::CodeInjection: {
            if (bytes.size() < 5) {
                setStatus("Need at least 5 bytes for code injection.", false);
                return;
            }
            QStringList lines;
            lines << "[ENABLE]";
            lines << QString("patch %1 90 90 90 90 90").arg(addrStr);
            lines << QString("; original %1").arg(bytesJoined);
            lines << QString();
            lines << "[DISABLE]";
            lines << QString("restore %1").arg(addrStr);
            script = lines.join('\n');
            break;
        }
        case TemplateKind::AobInjection: {
            QString pattern = bytesJoined;
            QStringList lines;
            lines << "[ENABLE]";
            lines << QString("aobscanmodule(INJECT,$process,%1)").arg(pattern);
            lines << "patch INJECT 90 90 90 90 90";
            lines << QString("; original %1").arg(pattern);
            lines << QString();
            lines << "[DISABLE]";
            lines << "restore INJECT";
            script = lines.join('\n');
            break;
        }
        case TemplateKind::Empty:
            script = "[ENABLE]\n\n[DISABLE]\n";
            break;
    }

    editor_->setPlainText(script);
    setStatus("Template generated.", true);
}

void AutoAssemblerDialog::onGenerateTemplate() {
    insertTemplate(TemplateKind::CodeInjection);
}

QString AutoAssemblerDialog::buildScriptFromEditor() const {
    QString script = editor_ ? editor_->toPlainText().trimmed() : QString();
    if (script.isEmpty()) return script;
    if (!script.contains("[ENABLE]", Qt::CaseInsensitive)) {
        script = QString("[ENABLE]\n%1\n\n[DISABLE]\n").arg(script);
    }
    return script;
}

void AutoAssemblerDialog::onAddToTable() {
    QString script = buildScriptFromEditor().trimmed();
    if (script.isEmpty()) {
        QMessageBox::warning(this, "Auto Assembler", "Script is empty.");
        return;
    }
    QString name = scriptNameEdit_ ? scriptNameEdit_->text().trimmed() : QString();
    if (name.isEmpty()) {
        name = templateAddress_ ? QString("Script %1").arg(QString::number(templateAddress_, 16))
                                : QStringLiteral("Auto Script");
    }
    emit scriptReady(name, script);
    setStatus("Script sent to table", true);
}

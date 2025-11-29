#pragma once

#include <QDialog>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <optional>

class QPlainTextEdit;
class QPushButton;
class QLabel;
class QTextEdit;
class QLineEdit;
class QSpinBox;
class QToolButton;
class QMenu;

namespace core {
class CodeInjector;
}

class AutoAssemblerDialog : public QDialog {
    Q_OBJECT
public:
    AutoAssemblerDialog(core::CodeInjector *injector, QWidget *parent = nullptr);
    void setInjectionContext(uintptr_t address, const std::vector<uint8_t> &originalBytes);
    void setScriptForEditing(const QString &name, const QString &script);
    bool executeScriptText(const QString &script, bool enable, QString *logOut = nullptr);

signals:
    void scriptReady(const QString &name, const QString &scriptText);

private slots:
    void onEnable();
    void onDisable();
    void onGenerateTemplate();
    void onAddToTable();

private:
    core::CodeInjector *injector_{};
    QPlainTextEdit *editor_{};
    QPushButton *enableBtn_{};
    QPushButton *disableBtn_{};
    QToolButton *templateButton_{};
    QMenu *templateMenu_{};
    QPushButton *addToTableBtn_{};
    QLineEdit *scriptNameEdit_{};
    QLabel *statusLabel_{};
    QTextEdit *log_{};
    QLineEdit *templateAddressEdit_{};
    QSpinBox *templateSizeSpin_{};
    QLabel *templateHint_{};
    uintptr_t templateAddress_{0};
    std::vector<uint8_t> templateBytes_;

    bool enabled_{false};

    struct Command {
        enum class Type { Patch, Restore };
        Type type;
        uintptr_t address;
        std::vector<uint8_t> bytes;
    };

    using CommandList = std::vector<Command>;
    std::optional<Command> parseLine(const std::string &line, QString &errorOut,
                                     const std::unordered_map<std::string, uintptr_t> &symbols) const;
    std::pair<CommandList, CommandList> parseSections(const QString &text, QStringList &errors);
    void setStatus(const QString &text, bool ok);
    void applyCommands(const CommandList &cmds);
    void restoreCommands(const CommandList &cmds);
    std::optional<uintptr_t> scanAob(const std::string &pattern, QString &errorOut,
                                     const std::string &moduleFilter = std::string()) const;
    bool parseAddressWithSymbols(const std::string &addrStr,
                                 const std::unordered_map<std::string, uintptr_t> &symbols,
                                 uintptr_t &outAddr, QString &errorOut) const;
    std::unordered_map<std::string, uintptr_t> collectModuleBases() const;
    std::unordered_map<std::string, uintptr_t> symbols_;
    CommandList lastEnable_;
    CommandList lastDisable_;

    enum class TemplateKind { CodeInjection, AobInjection, Empty };
    void insertTemplate(TemplateKind kind);
    QString joinBytes(const std::vector<uint8_t> &bytes, const QString &sep) const;
    std::vector<uint8_t> ensureTemplateBytes(uintptr_t address, QString &errorOut) const;
    QString buildScriptFromEditor() const;
};

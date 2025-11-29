#include "gui/ProcessListModel.h"

ProcessListModel::ProcessListModel(QObject *parent) : QAbstractListModel(parent) {
    refresh();
}

int ProcessListModel::rowCount(const QModelIndex &parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(processes_.size());
}

QVariant ProcessListModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) return {};
    const auto &p = processes_[index.row()];
    if (role == Qt::DisplayRole) {
        return QString::fromStdString(std::to_string(p.pid) + " - " + p.name);
    }
    return {};
}

void ProcessListModel::refresh() {
    beginResetModel();
    processes_ = core::ProcessEnumerator::list();
    endResetModel();
}

core::ProcessInfo ProcessListModel::processAt(int row) const {
    if (row < 0 || row >= rowCount()) return core::ProcessInfo{};
    return processes_[row];
}


#pragma once

#include <QAbstractListModel>
#include "core/ProcessEnumerator.h"

class ProcessListModel : public QAbstractListModel {
    Q_OBJECT
public:
    explicit ProcessListModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    void refresh();
    core::ProcessInfo processAt(int row) const;

private:
    std::vector<core::ProcessInfo> processes_;
};


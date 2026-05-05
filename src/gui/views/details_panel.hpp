#pragma once

#include <QWidget>

#include "core/result.hpp"

QT_BEGIN_NAMESPACE
namespace Ui { class DetailsPanel; }
QT_END_NAMESPACE

namespace sps::gui {

class DetailsPanel : public QWidget {
    Q_OBJECT
public:
    explicit DetailsPanel(QWidget* parent = nullptr);
    ~DetailsPanel();

    void showResult(const core::ScanResult& r);
    void clear();

private:
    Ui::DetailsPanel* ui_ = nullptr;
};

} // namespace sps::gui

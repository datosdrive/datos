// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2014-2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/dash-config.h>
#endif

#include <qt/splashscreen.h>


#include <chainparams.h>
#include <clientversion.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <qt/guiutil.h>
#include <qt/networkstyle.h>
#include <ui_interface.h>
#include <util/system.h>
#include <util/translation.h>

#include <QApplication>
#include <QCloseEvent>
#include <QDesktopWidget>
#include <QPainter>
#include <QScreen>


SplashScreen::SplashScreen(interfaces::Node& node, Qt::WindowFlags f, const NetworkStyle *networkStyle) :
    QWidget(nullptr, f), curAlignment(0), m_node(node)
{
    setWindowFlags(Qt::FramelessWindowHint| Qt::WindowSystemMenuHint);

    // set reference point, paddings
    int paddingLeft = 390;
    int paddingTop = 410;
    int titleCopyrightVSpace = 32;
    float fontFactor = 1.0;
    float devicePixelRatio = 1.0;
    QString font = QApplication::font().toString();

    // define text to place
    QString copyrightText = QChar(0xA9) + QString("2023 ") + QString(tr("DatosDrive"));
    QString titleAddText = networkStyle->getTitleAddText();

    // create a bitmap according to device pixelratio
    QSize splashSize(500*devicePixelRatio,500*devicePixelRatio);
    pixmap = QPixmap(splashSize);
    QPainter pixPaint(&pixmap);
    pixPaint.setPen(QColor(0,0,0));

    // draw a slightly radial gradient
    QRect rectIcon(QPoint(10,0), QSize(500,500));
    const QSize requiredSize(500,500);
    QPixmap icon(networkStyle->getSplashImage());
    QRadialGradient gradient(QPoint(0,0), splashSize.width()/devicePixelRatio);
    gradient.setColorAt(0, Qt::white);
    gradient.setColorAt(1, QColor(247,247,247));
    QRect rGradient(QPoint(0,0), splashSize);
    pixPaint.fillRect(rGradient, gradient);
    pixPaint.drawPixmap(rectIcon, icon);

    // copyright information
    pixPaint.setFont(QFont(font, 8 * fontFactor));
    pixPaint.drawText(paddingLeft, paddingTop + titleCopyrightVSpace + 48, copyrightText);

    // draw additional text if special network
    if (!titleAddText.isEmpty()) {
        QFont boldFont = QFont(font, 10 * fontFactor);
        boldFont.setWeight(QFont::Bold);
        pixPaint.setFont(boldFont);
        QFontMetrics fm = pixPaint.fontMetrics();
        int titleAddTextWidth = fm.width(titleAddText);
        pixPaint.drawText(pixmap.width() - titleAddTextWidth - 10, pixmap.height() - 25, titleAddText);
    }

    pixPaint.end();

    // Resize window and move to center of desktop, disallow resizing
    QRect r(QPoint(), QSize(pixmap.size().width()/devicePixelRatio,pixmap.size().height()/devicePixelRatio));
    resize(r.size());
    setFixedSize(r.size());
    move(QApplication::desktop()->screenGeometry().center() - r.center());

    subscribeToCoreSignals();
    installEventFilter(this);
}

SplashScreen::~SplashScreen()
{
    unsubscribeFromCoreSignals();
}

bool SplashScreen::eventFilter(QObject * obj, QEvent * ev) {
    if (ev->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(ev);
        if (keyEvent->key() == Qt::Key_Q) {
            m_node.startShutdown();
        }
    }
    return QObject::eventFilter(obj, ev);
}

void SplashScreen::finish()
{
    /* If the window is minimized, hide() will be ignored. */
    /* Make sure we de-minimize the splashscreen window before hiding */
    if (isMinimized())
        showNormal();
    hide();
    deleteLater(); // No more need for this
}

static void InitMessage(SplashScreen *splash, const std::string &message)
{
    bool invoked = QMetaObject::invokeMethod(splash, "showMessage",
        Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(message)),
        Q_ARG(int, Qt::AlignBottom | Qt::AlignHCenter),
        Q_ARG(QColor, GUIUtil::getThemedQColor(GUIUtil::ThemedColor::DEFAULT)));
    assert(invoked);
}

static void ShowProgress(SplashScreen *splash, const std::string &title, int nProgress, bool resume_possible)
{
    InitMessage(splash, title + std::string("\n") +
            (resume_possible ? _("(press q to shutdown and continue later)").translated
                                : _("press q to shutdown").translated) +
            strprintf("\n%d", nProgress) + "%");
}
#ifdef ENABLE_WALLET
void SplashScreen::ConnectWallet(std::unique_ptr<interfaces::Wallet> wallet)
{
    m_connected_wallet_handlers.emplace_back(wallet->handleShowProgress(std::bind(ShowProgress, this, std::placeholders::_1, std::placeholders::_2, false)));
    m_connected_wallets.emplace_back(std::move(wallet));
}
#endif

void SplashScreen::subscribeToCoreSignals()
{
    // Connect signals to client
    m_handler_init_message = m_node.handleInitMessage(std::bind(InitMessage, this, std::placeholders::_1));
    m_handler_show_progress = m_node.handleShowProgress(std::bind(ShowProgress, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
#ifdef ENABLE_WALLET
    m_handler_load_wallet = m_node.handleLoadWallet([this](std::unique_ptr<interfaces::Wallet> wallet) { ConnectWallet(std::move(wallet)); });
#endif
}

void SplashScreen::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    m_handler_init_message->disconnect();
    m_handler_show_progress->disconnect();
#ifdef ENABLE_WALLET
    m_handler_load_wallet->disconnect();
#endif // ENABLE_WALLET
    for (const auto& handler : m_connected_wallet_handlers) {
        handler->disconnect();
    }
    m_connected_wallet_handlers.clear();
    m_connected_wallets.clear();
}

void SplashScreen::showMessage(const QString &message, int alignment, const QColor &color)
{
    curMessage = message;
    curAlignment = alignment;
    curColor = color;
    update();
}

void SplashScreen::paintEvent(QPaintEvent *event)
{
    QPainter painter(this);
    QFont messageFont = GUIUtil::getFontNormal();
    messageFont.setPointSize(14);
    painter.setFont(messageFont);
    painter.drawPixmap(0, 0, pixmap);
    QRect r = rect().adjusted(5, 5, -5, -15);
    painter.setPen(curColor);
    painter.drawText(r, curAlignment, curMessage);
}

void SplashScreen::closeEvent(QCloseEvent *event)
{
    m_node.startShutdown(); // allows an "emergency" shutdown during startup
    event->ignore();
}

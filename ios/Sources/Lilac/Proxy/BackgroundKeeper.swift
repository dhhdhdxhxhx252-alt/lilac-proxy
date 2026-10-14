//
//  BackgroundKeeper.swift
//  Удержание процесса в фоне через обновления геопозиции — тот же приём, что в upstream.
//

import CoreLocation
import Foundation

/// iOS не даёт обычному приложению держать TCP-сервер в фоне. Постоянные (очень грубые)
/// обновления геопозиции не дают процессу уссть, и слушатель на 127.0.0.1 остаётся жив.
final class BackgroundKeeper: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published private(set) var active = false
    @Published private(set) var status: String?

    private let manager = CLLocationManager()

    func activate() {
        guard !active else { return }
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyThreeKilometers
        manager.distanceFilter = 3000
        manager.pausesLocationUpdatesAutomatically = false
        manager.activityType = .otherNavigation
        if manager.authorizationStatus == .authorizedAlways {
            manager.allowsBackgroundLocationUpdates = true
        } else {
            status = "Фон держится только до сворачивания: нужно разрешение «Всегда»"
        }
        manager.startUpdatingLocation()
        active = true
    }

    func deactivate() {
        guard active else { return }
        manager.stopUpdatingLocation()
        manager.allowsBackgroundLocationUpdates = false
        active = false
    }

    func locationManager(_ manager: CLLocationManager, didChangeAuthorization status: CLAuthorizationStatus) {
        if status == .authorizedAlways {
            manager.allowsBackgroundLocationUpdates = true
        }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        status = "Геолокация недоступна: \(error.localizedDescription)"
    }
}

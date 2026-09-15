import pandas as pd
import numpy as np

# Détection grossière car présuppose un réseau plutôt gaussien, ce qui n'est pas le cas de la plupart des réseaux

def detect_anomalies_zscore(series: pd.Series, threshold: float = 3.0) -> pd.DataFrame:
    """
    Détecte les anomalies dans une série temporelle via zscore
    threshold : nbr d'écarts types au dela duquel on considère un pt comme anormal
    Retourne un DataFrame avec un z_score pour chaque pt + bool anomalie
    """

    mean = series.mean()
    std = series.std()

    z_score = (series - mean) / std

    result = pd.DataFrame({
        "value": series,
        "z_score": z_score,
        "is_anomaly": np.abs(z_score) > threshold
    })

    return result

# meilleure approche : détection via MAD, plus robustes aux distribs asymétriques

def detect_anomalies_mad(series: pd.Series, threshold: float = 3.5) -> pd.DataFrame:
    """
    Détection via MAD (Median Absolute Deviation)
    """
    median = series.median()
    mad = np.median(np.abs(series - median))

    # facteur de 0.6745 pour rendre le MAD comparable à l'écart type pour une distribution normale
    modified_z_score = 0.6745 * (series - median) / mad

    result = pd.DataFrame({
        "value": series,
        "modified_z_score": modified_z_score,
        "is_anomaly": np.abs(modified_z_score) > threshold
    })

    return result
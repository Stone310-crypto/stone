use super::{GameEconomyError, GameGenre};



pub fn validate_genres(genres: &[GameGenre]) -> Result<(), GameEconomyError> {
    if genres.is_empty() {
        return Err(GameEconomyError::InvalidInput {
            reason: "Mindestens 1 Genre erforderlich".into(),
        });
    }

    if genres.len() > 5 {
        return Err(GameEconomyError::InvalidInput {
            reason: "Maximal 5 Genres pro Spiel (bitte auf Kerngenres konzentrieren)".into(),
        });
    }

    // Duplikate prüfen
    let mut sorted = genres.to_vec();
    sorted.sort();
    for i in 0..sorted.len() - 1 {
        if sorted[i] == sorted[i + 1] {
            return Err(GameEconomyError::InvalidInput {
                reason: format!("Genre-Duplikat: {}", sorted[i]),
            });
        }
    }

    Ok(())
}

/// Parse mehrere Genres aus komma-separierten Strings.
/// z.B. "rpg, blockchain gaming, crafting" → vec![GameGenre::RPG, GameGenre::BlockchainGaming, GameGenre::Crafting]
pub fn parse_genre_list(input: &str) -> Result<Vec<GameGenre>, String> {
    let mut result = Vec::new();
    for part in input.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        match GameGenre::from_str(trimmed) {
            Some(genre) => result.push(genre),
            None => return Err(format!("Unbekanntes Genre: '{}'. Erlaubt: {:?}", trimmed, GameGenre::all_names())),
        }
    }
    if result.is_empty() {
        return Err("Keine gültigen Genres gefunden".into());
    }
    validate_genres(&result)
        .map_err(|e| format!("Genre-Validierung fehlgeschlagen: {}", e))?;
    Ok(result)
}

/// Genre-Filtermöglichkeiten (für Dashboard/API)
#[derive(Clone, Debug)]
pub struct GenreFilter {
    pub genres: Option<Vec<GameGenre>>,  // AND-Filter: Spiel muss ALLE haben
    pub any_genres: Option<Vec<GameGenre>>,  // OR-Filter: Spiel muss MINDESTENS EINS haben
}

impl GenreFilter {
    pub fn matches(&self, game_genres: &[GameGenre]) -> bool {
        if let Some(ref must_have) = self.genres {
            if !must_have.iter().all(|g| game_genres.contains(g)) {
                return false;
            }
        }
        if let Some(ref any) = self.any_genres {
            if !any.iter().any(|g| game_genres.contains(g)) {
                return false;
            }
        }
        true
    }
}
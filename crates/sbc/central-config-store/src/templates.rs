//! Global config templates and per-site materialization (§5.4, §8).
//!
//! A template is a fleet-baseline trunk group or dial plan authored once
//! and assigned to many sites with a rollout ring. *Materializing* a
//! template writes its data into each assigned site's shard as an ordinary
//! synced row (stamped `updated_by = 'template'`), bumping that site's
//! epoch so the sync agent picks it up. Sites with a local override of the
//! same id (a row written by an operator, `updated_by = <subject>`) are
//! skipped — overrides win. Materializing "up to ring N" lets a change be
//! proven on the canary ring before promotion.

use serde_json::Value;
use sqlx::Row;

use crate::error::{CentralError, CentralResult};
use crate::model::{ChangeOp, MaterializeReport, SiteMaterialization, TemplateKind};
use crate::store::{CentralConfigStore, bump_epoch, journal};

/// `updated_by` marker on materialized rows; distinguishes them from
/// operator-written overrides so materialization knows what it may
/// overwrite.
const TEMPLATE_ORIGIN: &str = "template";

impl CentralConfigStore {
    /// Create or update a global template.
    ///
    /// # Errors
    /// [`CentralError::Storage`] on DB failure.
    pub async fn upsert_template(
        &self,
        kind: TemplateKind,
        id: &str,
        data: &Value,
        actor: &str,
    ) -> CentralResult<()> {
        sqlx::query(
            "INSERT INTO config_templates (kind, id, data, updated_by)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (kind, id) DO UPDATE SET
                 data = EXCLUDED.data, updated_by = EXCLUDED.updated_by, updated_at = NOW()",
        )
        .bind(kind.as_str())
        .bind(id)
        .bind(data)
        .bind(actor)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Assign a template to a site in a rollout ring (re-assigning updates
    /// the ring). The assignment alone changes nothing at the site until
    /// [`materialize_template`](Self::materialize_template) runs.
    ///
    /// # Errors
    /// [`CentralError::Storage`] — including a foreign-key violation if the
    /// template or site doesn't exist.
    pub async fn assign_template(
        &self,
        kind: TemplateKind,
        template_id: &str,
        site_code: &str,
        ring: i32,
    ) -> CentralResult<()> {
        sqlx::query(
            "INSERT INTO template_assignments (kind, template_id, site_code, ring)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (kind, template_id, site_code) DO UPDATE SET ring = EXCLUDED.ring",
        )
        .bind(kind.as_str())
        .bind(template_id)
        .bind(site_code)
        .bind(ring)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Materialize a template into every assigned site whose ring is `<=
    /// up_to_ring`. Sites with a local override are left alone. Returns a
    /// per-site report.
    ///
    /// # Errors
    /// [`CentralError::NotFound`] if the template doesn't exist, or
    /// [`CentralError::Storage`].
    pub async fn materialize_template(
        &self,
        kind: TemplateKind,
        template_id: &str,
        up_to_ring: i32,
    ) -> CentralResult<MaterializeReport> {
        let data: Option<Value> =
            sqlx::query_scalar("SELECT data FROM config_templates WHERE kind = $1 AND id = $2")
                .bind(kind.as_str())
                .bind(template_id)
                .fetch_optional(self.pool())
                .await?;
        let data = data.ok_or(CentralError::NotFound)?;

        let rows = sqlx::query(
            "SELECT site_code, ring FROM template_assignments
             WHERE kind = $1 AND template_id = $2 ORDER BY site_code",
        )
        .bind(kind.as_str())
        .bind(template_id)
        .fetch_all(self.pool())
        .await?;

        let mut sites = Vec::with_capacity(rows.len());
        for row in &rows {
            let site: String = row.try_get("site_code")?;
            let ring: i32 = row.try_get("ring")?;
            if ring > up_to_ring {
                sites.push(SiteMaterialization::SkippedRing {
                    site_code: site,
                    ring,
                });
                continue;
            }
            match self
                .materialize_one(kind, template_id, &site, &data)
                .await?
            {
                Some(epoch) => sites.push(SiteMaterialization::Applied {
                    site_code: site,
                    epoch,
                }),
                None => sites.push(SiteMaterialization::SkippedOverridden { site_code: site }),
            }
        }
        Ok(MaterializeReport {
            kind,
            template_id: template_id.to_string(),
            up_to_ring,
            sites,
        })
    }

    /// Delete a template: tombstone its materialized rows at assigned sites
    /// (overrides untouched), then remove the template and its assignments
    /// (cascade).
    ///
    /// # Errors
    /// [`CentralError::Storage`] on DB failure.
    pub async fn delete_template(
        &self,
        kind: TemplateKind,
        template_id: &str,
    ) -> CentralResult<()> {
        let sites: Vec<String> = sqlx::query_scalar(
            "SELECT site_code FROM template_assignments WHERE kind = $1 AND template_id = $2",
        )
        .bind(kind.as_str())
        .bind(template_id)
        .fetch_all(self.pool())
        .await?;
        for site in &sites {
            self.unmaterialize_one(kind, template_id, site).await?;
        }
        // Cascade removes the assignments.
        sqlx::query("DELETE FROM config_templates WHERE kind = $1 AND id = $2")
            .bind(kind.as_str())
            .bind(template_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The current origin of a live shard row, or `None` if absent.
    async fn row_origin(
        &self,
        kind: TemplateKind,
        site_code: &str,
        id: &str,
    ) -> CentralResult<Option<String>> {
        let sql = format!(
            "SELECT updated_by FROM {} WHERE site_code = $1 AND id = $2 AND NOT deleted",
            kind.target_table().name()
        );
        let origin: Option<String> = sqlx::query_scalar(&sql)
            .bind(site_code)
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        Ok(origin)
    }

    /// Write the template into one site's shard unless an override exists.
    /// Returns the new epoch, or `None` if skipped (overridden).
    async fn materialize_one(
        &self,
        kind: TemplateKind,
        template_id: &str,
        site_code: &str,
        data: &Value,
    ) -> CentralResult<Option<i64>> {
        if let Some(origin) = self.row_origin(kind, site_code, template_id).await?
            && origin != TEMPLATE_ORIGIN
        {
            return Ok(None); // local override wins
        }
        let table = kind.target_table();
        let mut tx = self.pool().begin().await?;
        let epoch = bump_epoch(&mut tx, site_code).await?;
        // The WHERE on the UPDATE arm ensures that if an operator override
        // was written between the row_origin check above and this INSERT,
        // the UPDATE is a no-op (the override's updated_by != TEMPLATE_ORIGIN,
        // so the condition fails and the row is left untouched).
        let sql = format!(
            "INSERT INTO {} (site_code, id, data, revision, deleted, updated_by)
             VALUES ($1, $2, $3, $4, FALSE, $5)
             ON CONFLICT (site_code, id) DO UPDATE SET
                 data = EXCLUDED.data, revision = EXCLUDED.revision,
                 deleted = FALSE, updated_by = EXCLUDED.updated_by, updated_at = NOW()
             WHERE {}.updated_by = $5",
            table.name(),
            table.name()
        );
        let result = sqlx::query(&sql)
            .bind(site_code)
            .bind(template_id)
            .bind(data)
            .bind(epoch)
            .bind(TEMPLATE_ORIGIN)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(None);
        }
        journal(
            &mut tx,
            site_code,
            epoch,
            table,
            template_id,
            ChangeOp::Upsert,
            Some(data),
            TEMPLATE_ORIGIN,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(epoch))
    }

    /// Tombstone a site's materialized row for a template, but only if it
    /// is still template-origin (an override is left in place).
    async fn unmaterialize_one(
        &self,
        kind: TemplateKind,
        template_id: &str,
        site_code: &str,
    ) -> CentralResult<Option<i64>> {
        match self.row_origin(kind, site_code, template_id).await? {
            Some(origin) if origin == TEMPLATE_ORIGIN => {}
            _ => return Ok(None), // absent or overridden
        }
        let table = kind.target_table();
        let mut tx = self.pool().begin().await?;
        let epoch = bump_epoch(&mut tx, site_code).await?;
        // Guard against TOCTOU: only tombstone if the row is still
        // template-origin. An override written between the row_origin
        // check and this UPDATE will have a different updated_by, so the
        // WHERE clause makes this a no-op instead of clobbering it.
        let sql = format!(
            "UPDATE {} SET deleted = TRUE, revision = $1, updated_by = $2, updated_at = NOW()
             WHERE site_code = $3 AND id = $4 AND NOT deleted AND updated_by = $2",
            table.name()
        );
        let result = sqlx::query(&sql)
            .bind(epoch)
            .bind(TEMPLATE_ORIGIN)
            .bind(site_code)
            .bind(template_id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(None);
        }
        journal(
            &mut tx,
            site_code,
            epoch,
            table,
            template_id,
            ChangeOp::Delete,
            None,
            TEMPLATE_ORIGIN,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(epoch))
    }
}

-- updatedAt triggers for mutable tables: users, projects, video_jobs, providers
-- This function sets updated_at = NOW() on every UPDATE.

CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- users
DROP TRIGGER IF EXISTS set_updated_at_users ON users;
CREATE TRIGGER set_updated_at_users
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION trigger_set_updated_at();

-- projects
DROP TRIGGER IF EXISTS set_updated_at_projects ON projects;
CREATE TRIGGER set_updated_at_projects
  BEFORE UPDATE ON projects
  FOR EACH ROW
  EXECUTE FUNCTION trigger_set_updated_at();

-- video_jobs
DROP TRIGGER IF EXISTS set_updated_at_video_jobs ON video_jobs;
CREATE TRIGGER set_updated_at_video_jobs
  BEFORE UPDATE ON video_jobs
  FOR EACH ROW
  EXECUTE FUNCTION trigger_set_updated_at();

-- providers
DROP TRIGGER IF EXISTS set_updated_at_providers ON providers;
CREATE TRIGGER set_updated_at_providers
  BEFORE UPDATE ON providers
  FOR EACH ROW
  EXECUTE FUNCTION trigger_set_updated_at();

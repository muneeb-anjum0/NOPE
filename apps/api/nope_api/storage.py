from collections import OrderedDict

from nope_api.models import Project, Scan, new_id


class InMemoryStore:
    def __init__(self) -> None:
        self.projects: OrderedDict[str, Project] = OrderedDict()
        self.scans: OrderedDict[str, Scan] = OrderedDict()
        demo = Project(
            id="prj_demo",
            name="NOPE Local Demo",
            repository="Uploaded ZIP",
            target_url="https://example.com",
        )
        self.projects[demo.id] = demo

    def list_projects(self) -> list[Project]:
        return list(self.projects.values())

    def create_project(self, name: str, repository: str | None, target_url: str | None) -> Project:
        project = Project(id=new_id("prj"), name=name, repository=repository, target_url=target_url)
        self.projects[project.id] = project
        return project

    def save_scan(self, scan: Scan) -> Scan:
        self.scans[scan.id] = scan
        return scan

    def get_scan(self, scan_id: str) -> Scan | None:
        return self.scans.get(scan_id)

    def list_scans(self) -> list[Scan]:
        return list(reversed(self.scans.values()))


store = InMemoryStore()
